(function($){
    var kPbkdf2Iteration = 300000;
    var kTimeoutDuration = 600;

    var timeout = null;

    function showHidePassphrase() {
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

    var numBits = 256; // this needs to actually be dependent on desired key size, should make at least 256
    function GeneratePassword() {
        var passphrase = $('#passphrase').val();
        var sitename = $('#sitename').val();
        var customSalt = $('#customSalt').val();

        var salt = sjcl.hash.sha256.hash('brainpassSalt' + sitename + customSalt);
        var passphraseHash = sjcl.misc.pbkdf2(passphrase, salt, kPbkdf2Iteration, numBits);
        var hashString = sjcl.codec.hex.fromBits(passphraseHash);

        $('#hash').val(hashString);
        GenerateSitePassword(passphraseHash);
        ShowVerifier(hashString);
    }

    function GenerateSitePassword(hash) {
        var alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        var passwordLength = 20;
        var bitsLeft = numBits;
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
        $('#generatedPassword').val(passwordStr);
    }

    function ShowVerifier(hashString) {
        var verifierBytes = sjcl.hash.sha256.hash(hashString);
        var verifierHex = sjcl.codec.hex.fromBits(verifierBytes);
        $('#verifier').val(verifierHex);
    }

    function OnInputChange() {
        clearTimeout(timeout);
        timeout = setTimeout(function() {
            GeneratePassword();
        }, kTimeoutDuration);
    }

    function OnInput(id, func) {
        $(id).bind("input keyup keydown keypress change blur", function() {
            if ($(this).val() != jQuery.data(this, "lastvalue")) {
                func();
            }
            jQuery.data(this, "lastvalue", $(this).val());
        });
        $(id).bind("focus", function() {
           jQuery.data(this, "lastvalue", $(this).val());
        });
    }

    $(document).ready( function() {
        OnInput('#passphrase', OnInputChange);
        OnInput('#sitename', OnInputChange);
        OnInput('#customSalt', OnInputChange);
        $('#hidePassphrase').click(showHidePassphrase);
    });
})(jQuery);
