(function(global){
    var kPbkdf2Iteration = 300000;
    var kTimeoutDuration = 600;

    var timeout = null;

    // Crypto
    var numCryptoBits = 256; // this just needs to be large enough to cover enough bits for the password. Assuming an alphanumeric password with roughly 6 bits per char, this can generate 42 unique password characters
    function GeneratePassword(passphrase, sitename, siteusername, customSalt) {
        // Generate the PBKDF2 hash first with all information taken into account, then use that hash to generate
        // the per-site password from the hash which is what we want.
        var salt = sjcl.hash.sha256.hash('brainpassSalt' + sitename + siteusername + customSalt);
        var passphraseHash = sjcl.misc.pbkdf2(passphrase, salt, kPbkdf2Iteration, numCryptoBits);
        var hashString = sjcl.codec.hex.fromBits(passphraseHash);

        var passwordStr = GenerateSitePassword(passphraseHash);
        var verifierHex = ShowVerifier(hashString);

        return {
            hashString: hashString,
            passwordStr: passwordStr,
            verifierHex: verifierHex
        };
    }

    function GenerateSitePassword(hash) {
        var alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        var passwordLength = 24;
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
        };
    }

    onmessage = function(message) { // these are only called when in the worker thread
        if (message.data.type == 'load') {
            window = global;
            importScripts('bitcoinjs-min.js', 'http://crypto.stanford.edu/sjcl/sjcl.js');
        }
        else if (message.data.type == 'generate') {
            var passwordResults = GeneratePassword(message.data.data.passphrase, message.data.data.sitename, message.data.data.siteusername, message.data.data.customSalt);
            postMessage(passwordResults);
        }
    };

    // UI
    function ShowProgressBar() {
        $('#generateProgressBar').toggle(true);
    }
    function HideProgressBar() {
        $('#generateProgressBar').toggle(false);
    }

    function ShowResults(results) {
        $('#hash').val(results.hashString);
        $('#generatedPassword').val(results.passwordStr);
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

    function OnInputChange() {
        clearTimeout(timeout);
        timeout = setTimeout(function() {
            var passphrase = $('#passphrase').val();
            var sitename = $('#sitename').val();
            var siteusername = $('#siteusername').val();
            var customSalt = $('#customSalt').val();

            if (asyncWorker) {
                ShowProgressBar();
                asyncWorker.postMessage({
                    type: 'generate',
                    data: {
                        passphrase: passphrase,
                        sitename: sitename,
                        siteusername: siteusername,
                        customSalt: customSalt
                    }
                });
            }
            else {
                var passwordResults = GeneratePassword(passphrase, sitename, siteusername, customSalt);
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

            SetupWebWorker();
        });
    }
})(this);
