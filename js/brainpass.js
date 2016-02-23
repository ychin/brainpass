(function(global){
    var kPbkdf2Iteration = 100000;
    var kTimeoutDuration = 600;
    var kPasswordLength = 16;
    var kDefaultPassphraseGenEntropy = 60; // 60 bits should be roughly enough. "correct horse battery staple" only has 44

    var kInWebWorker = (typeof window === 'undefined');

    var gUseSymbolsForPassword = false; // pass this to web worker
    var gResults = null;

    var timeout = null;

    // Crypto
    var numCryptoBits = 256; // this just needs to be large enough to cover enough bits for the password. Assuming an alphanumeric password with roughly 6 bits per char, this can generate 42 unique password characters
    function GeneratePassword(config) {
        // Generate the PBKDF2 hash first with all information taken into account, then use that hash to generate
        // the per-site password from the hash which is what we want.
        var passphrase = config.passphrase;
        var sitename = config.sitename;
        var siteusername = config.siteusername;
        var customSalt = config.customSalt;
        var hashIterations = config.hashIterations;
        var passwordLength = config.passwordLength;

        var useSymbolsForPassword = config.useSymbolsForPassword;

        var salt = sjcl.hash.sha256.hash('brainpassSalt' + sitename + siteusername + customSalt);
        var passphraseHash = sjcl.misc.pbkdf2(passphrase, salt, hashIterations, numCryptoBits);
        var hashString = sjcl.codec.hex.fromBits(passphraseHash);

        var passwordStr = GenerateSitePassword(passwordLength, passphraseHash, useSymbolsForPassword);

        return {
            hashString: hashString,
            passphraseHash: passphraseHash,
            passwordStr: passwordStr
        };
    }

    function GenerateSitePassword(passwordLength, hash, useSymbolsForPassword) {
        var alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        var symbols = '!@#%^&*()-=`~[]\\|;:,./<>?'; // omitted '"$ because seems like some sites don't accept them
        if (useSymbolsForPassword)
            alphabet += symbols;

        var base = BigInteger.valueOf(alphabet.length);
        var password = new Array(passwordLength);
        var hashBytes = sjcl.codec.bytes.fromBits(hash);
        var hashBigNum = BigInteger.fromByteArrayUnsigned(hashBytes);

        for (var passwordI = 0; passwordI < passwordLength; ++passwordI) {
            var mod = hashBigNum.mod(base);
            password[passwordI] = alphabet[mod.intValue()];
            hashBigNum = hashBigNum.subtract(mod).divide(base);
        }
        var passwordStr = password.join('');
        return passwordStr;
    }

    // Passphrase Generator
    if (!kInWebWorker) {
        var gPassphraseGeneratorLocales = {
            en: {
                wordlist: en_wordlist,
                useSpace: true
            },
            zhtw: {
                wordlist: zhtw_wordlist,
                useSpace: false
            },
            zhcn: {
                wordlist: zhcn_wordlist,
                useSpace: false
            }
        };
        var gPassphraseGeneratorLocale = gPassphraseGeneratorLocales.en;
    }

    function GeneratePassphrase() {
        // Pick passphrase
        var newPassphrase = GenRandomLocalePassphrase();
        $('#passphrase').val(newPassphrase);

        // Update UI and regenerate password
        if ($('#passphrase').attr('type') == 'password') {
            ShowHidePassphrase(); // we have to show the passphrase if it's randomly generated so the user can actually see it
        }
        OnInputChange();
    }

    function UpdateRandPassphraseLanguage() {
        var id = $(this).attr('id');
        switch (id) {
            case 'randZHTW':
                gPassphraseGeneratorLocale = gPassphraseGeneratorLocales.zhtw;
                break;
            case 'randZHCN':
                gPassphraseGeneratorLocale = gPassphraseGeneratorLocales.zhcn;
                break;
            case 'randEN':
            default:
                gPassphraseGeneratorLocale = gPassphraseGeneratorLocales.en;
                break;
        }
    }

    function GenRandomLocalePassphrase() {
        var useSpace = gPassphraseGeneratorLocale.useSpace;
        var wordlist = gPassphraseGeneratorLocale.wordlist;

        // Decide on entropy
        var passphraseEntropy = parseInt($('#configPassphraseGenEntropy').val());
        if (isNaN(passphraseEntropy) || passphraseEntropy < 1) {
            passphraseEntropy = kDefaultPassphraseGenEntropy;
        }
        var entropyBitsPerWord = Math.log(wordlist.length) / Math.LN2;
        var numWordsToPick = Math.ceil(passphraseEntropy / entropyBitsPerWord);

        // Generate the passphrase
        var newPassphrase = new Array(numWordsToPick);

        if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
            for (var i = 0; i < 10; ++i) {
                Math.random(); // just prime the rand gen in this case, although ideally we really should use window.crypto
            }
            for (var i = 0; i < numWordsToPick; ++i) {
                var index = Math.floor(Math.random() * wordlist.length);
                newPassphrase[i] = wordlist[index];
            }
        }
        else {
            var indices = new Uint32Array(numWordsToPick);
            crypto.getRandomValues(indices);
            for (var i = 0; i < numWordsToPick; ++i) {
                newPassphrase[i] = wordlist[indices[i] % wordlist.length];
            }
        }

        return newPassphrase.join(useSpace ? ' ' : '');
    }

    // Web Worker async
    var asyncWorker;
    var gWorkerRunning = false;
    var gQueuedAsyncGeneration = null;
    function SetupWebWorker() {
        if (typeof Worker === 'undefined') {
            return;
        }

        try {
            asyncWorker = new Worker('js/brainpass.js');
        }
        catch (e) {
            asyncWorker = undefined;
            return;
        }

        asyncWorker.postMessage({type:'load'}); // this will start the worker
        asyncWorker.onmessage = function(message) {
            ShowResults(message.data);
            HideProgressBar();

            if (gQueuedAsyncGeneration) {
                ShowProgressBar();
                asyncWorker.postMessage({
                    type: 'generate',
                    data: gQueuedAsyncGeneration
                });
                gQueuedAsyncGeneration = null;
            }
            else {
                gWorkerRunning = false;
            }
        };
    }

    onmessage = function(message) { // these are only called when in the worker thread
        if (message.data.type == 'load') {
            window = global; // bitcoin-js relies on "window" object unfortunately
            importScripts('external/bitcoinjs-min.js', 'external/sjcl.js', 'external/codecBytes.js');
        }
        else if (message.data.type == 'generate') {
            var passwordResults = GeneratePassword(message.data.data);
            postMessage(passwordResults);
        }
    };

    // UI
    function ShowProgressBar() {
        $('#generateProgressBar').toggle(true);
        $('#activateSymbols').attr('disabled', true);
    }
    function HideProgressBar() {
        $('#generateProgressBar').toggle(false);
    }

    function ShowResults(results) {
        gResults = results;
        $('#hash').val(results.hashString);
        $('#generatedPassword').val(results.passwordStr);
        $('#activateSymbols').attr('disabled', false);
    }

    function ShowHidePassphrase() {
        var pass = $('#passphrase');
        if (pass.attr('type') == 'password') {
            pass.attr('type', 'text');
            $('#hidePassphrase').html('Hide');
        }
        else {
            pass.attr('type', 'password');
            $('#hidePassphrase').html('Show');
        }
    }

    function ToggleSymbols() {
        var oldActivated = $('#activateSymbols').hasClass('active');
        var activated = !oldActivated;
        gUseSymbolsForPassword = activated;
        if (gResults) {
            gResults.passwordStr = GenerateSitePassword(kPasswordLength, gResults.passphraseHash, gUseSymbolsForPassword);
            ShowResults(gResults);
        }
    }

    function UpdatePasswordLength() {
        kPasswordLength = parseInt($('#configPasswordLength').val());
        if (kPasswordLength < 1 || isNaN(kPasswordLength))
            kPasswordLength = 1;
        if (gResults) {
            gResults.passwordStr = GenerateSitePassword(kPasswordLength, gResults.passphraseHash, gUseSymbolsForPassword);
            ShowResults(gResults);
        }
    }

    function OnInputChange() {
        clearTimeout(timeout);
        timeout = setTimeout(function() {
            var passphrase = $('#passphrase').val();
            var sitename = $('#sitename').val();
            var siteusername = $('#siteusername').val();
            var customSalt = $('#customSalt').val();

            var newHashIterations = parseInt($('#configHashIterations').val());

            var generateConfig = {
                passphrase: passphrase,
                sitename: sitename.trim(),
                siteusername: siteusername.trim(),
                customSalt: customSalt,
                useSymbolsForPassword: gUseSymbolsForPassword,
                passwordLength: kPasswordLength,
                hashIterations: isNaN(newHashIterations) ? kPbkdf2Iteration : newHashIterations
            };

            if (asyncWorker) {
                ShowProgressBar();
                if (gWorkerRunning) {
                    gQueuedAsyncGeneration = generateConfig;
                }
                else {
                    gWorkerRunning = true;
                    asyncWorker.postMessage({
                        type: 'generate',
                        data: generateConfig
                    });
                }
            }
            else {
                var passwordResults = GeneratePassword(generateConfig);
                ShowResults(passwordResults);
            }
        }, kTimeoutDuration);
    }

    function OnInput(id, func) {
        $(id).bind("input change", function() {
            if ($(this).val() != jQuery.data(this, "lastvalue")) {
                func();
            }
            jQuery.data(this, "lastvalue", $(this).val());
        });
        $(id).bind("focus", function() {
           jQuery.data(this, "lastvalue", $(this).val());
        });
    }

    if (!kInWebWorker) {
        $(document).ready( function() {
            // Redirect to HTTPS if we're in insecure channels. This helps prevent MITM attack that may inject source code that listens on the password
            // This obviously won't help if the HTTP version has indeed been MITM attacked, but it would set the expectation that this should run
            // under HTTPS so bookmarks etc would be directed at the secure version instead.
            if (window.location.protocol == 'http:') {
                window.location.protocol = 'https:';
            }

            $('#generatePassphrase').click(GeneratePassphrase);
            $('#randPassphraseLang label input').on('change', UpdateRandPassphraseLanguage);
            $('#hidePassphrase').click(ShowHidePassphrase);
            $('#activateSymbols').click(ToggleSymbols);
            //$('#generatedPassword').focus(function () { this.select();});
            $('#generatedPassword').click(function () { this.select();});

            $('#configPasswordLength').val(kPasswordLength);
            OnInput('#configPasswordLength', UpdatePasswordLength);
            $('#configHashIterations').val(kPbkdf2Iteration);
            $('#configPassphraseGenEntropy').val(kDefaultPassphraseGenEntropy);

            var elemsNeedInput = ['#passphrase', '#sitename', '#siteusername', '#customSalt', '#configHashIterations'];
            for (var i = 0; i < elemsNeedInput.length; ++i) {
                OnInput(elemsNeedInput[i], OnInputChange);
            }

            SetupWebWorker();
        });
    }
})(this);
