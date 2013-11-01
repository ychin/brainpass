(function(global){
    var kPbkdf2Iteration = 100000;
    var kTimeoutDuration = 600;

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

        var useSymbolsForPassword = config.useSymbolsForPassword;

        var salt = sjcl.hash.sha256.hash('brainpassSalt' + sitename + siteusername + customSalt);
        var passphraseHash = sjcl.misc.pbkdf2(passphrase, salt, kPbkdf2Iteration, numCryptoBits);
        var hashString = sjcl.codec.hex.fromBits(passphraseHash);

        var passwordStr = GenerateSitePassword(passphraseHash, useSymbolsForPassword);
        var verifierHex = ShowVerifier(hashString);

        return {
            hashString: hashString,
            passphraseHash: passphraseHash,
            passwordStr: passwordStr,
            verifierHex: verifierHex
        };
    }

    function GenerateSitePassword(hash, useSymbolsForPassword) {
        var alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        var symbols = '!@#%^&*()-=`~[]\\|;:,./<>?'; // omitted '"$ because seems like some sites don't accept them
        if (useSymbolsForPassword)
            alphabet += symbols;
        var passwordLength = 16;
        var base = BigInteger.valueOf(alphabet.length);
        var password = new Array(passwordLength);
        var hashString = sjcl.codec.hex.fromBits(hash);
        var hashBytes = Crypto.util.hexToBytes(hashString);
        var hashBigNum = BigInteger.fromByteArrayUnsigned(hashBytes);
        for (var passwordI = 0; passwordI < passwordLength; ++passwordI) {
            var mod = hashBigNum.mod(base);
            password[passwordI] = alphabet[mod.intValue()];
            hashBigNum = hashBigNum.subtract(mod).divide(base);
        }
        var passwordStr = password.join('');
        return passwordStr;
    }

    function ShowVerifier(hashString) {
        var verifierBytes = sjcl.hash.sha256.hash(hashString);
        var verifierHex = sjcl.codec.hex.fromBits(verifierBytes);
        return verifierHex;
    }

    // Web Worker async
    var asyncWorker;
    var gWorkerRunning = false;
    var gQueuedAsyncGeneration = null;
    function SetupWebWorker() {
        if (Worker === undefined) {
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
            window = global;
            importScripts('bitcoinjs-min.js', 'http://crypto.stanford.edu/sjcl/sjcl.js');
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
        $('#verifier').val(results.verifierHex);
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
            gResults.passwordStr = GenerateSitePassword(gResults.passphraseHash, gUseSymbolsForPassword);
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

            var generateConfig = {
                passphrase: passphrase,
                sitename: sitename,
                siteusername: siteusername,
                customSalt: customSalt,
                useSymbolsForPassword: gUseSymbolsForPassword
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

    if (global.jQuery) { // this is not defined when in web worker
        $(document).ready( function() {
            var elemsNeedInput = ['#passphrase', '#sitename', '#siteusername', '#customSalt'];
            for (var i = 0; i < elemsNeedInput.length; ++i) {
                OnInput(elemsNeedInput[i], OnInputChange);
            }

            $('#hidePassphrase').click(ShowHidePassphrase);
            $('#activateSymbols').click(ToggleSymbols);

            SetupWebWorker();
        });
    }
})(this);
