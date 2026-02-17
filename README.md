brainpass
=========

Brainpass is a utility web page to generate per-site passwords from a master passphrase, without needing external data. Similar to how brainwallet works. It does so by hashing together the master passphrase, website address, user name, and an optional salt to generate a unique password. As such, this is a completely stateless system without needing to store and synchronize an external database of all your passwords.

* The built-in passphrase generator allows you to generate passphrases randomly to remove human biases. You can pick among the different languages at the bottom (it defaults to English). This feature requires `Crypto.getRandomValues` to be supported in the web browser. The entropy for the passphrase can be tuned in the "Passphrase Generation entropy" section. In English, we use a word dictionary of 4337 words, so each word has ~12 bits of entropy. The default of 60-bit entropy means it generates a 5-word passphrase.

* The password hashing is done using PBKDF2. You can control the iteration count under the "Hash Iterations" part. Longer iterations are harder to crack. If you want to be more secure, use an iteration count that's long enough so that it's barely tolerable to use (since longer iteration count means it takes longer for you to generate a password as well).

* This web page uses an async web worker to hash the password. The async worker will be turned off when hosted on a file:// web page due to security limitations. This can be worked around by hosting a localhost server, e.g. running `python3 -m http.server` and then navigating to localhost:8000.

Please use this at your own risk. For a more comprehensive password solution, consider using a password manager. Note that if you use a low iteration count, it is possible for an attacker to reverse-hash your original passphrase, which would compromise all your other passwords.

TODOs:
- local storage stores websites for me, allow exporting to JSON
- verifier to make sure we typed the correct password
- Mobile improvements:
 - Auto-select the generated password to make copying easier
- Turn into app/browser extension to save typing and can auto-copy for us
