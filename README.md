brainpass
=========

Utility web page to generate per-site passwords from a master passphrase, without needing external data. Similar to how brainwallet works.

This web page uses an async web worker to hash the password. The async worker will be turned off when hosted on a file:// web page due to security limitations. This can be worked around by hosting a localhost server, e.g. running `python3 -m http.server` and then navigating to localhost:8000.

TODOs:
- local storage stores websites for me, allow exporting to JSON
- random passphrase generator
 - different languages
 - Choose how long password can be
- verifier to make sure we typed the correct password
- Use iframe sandbox
- Provide a default list of sites
- Expose password length
- Expose hash iteration count / algorithm
- Mobile improvements:
 - Auto-select the generated password to make copying easier
- Turn into app/browser extension to save typing and can auto-copy for us
