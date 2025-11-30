# Authentication Bypass Techniques 

This document is a general-purpose, high-detail reference for understanding and exploiting authentication vulnerabilities. It includes methodology, examples, and tables describing tool flags and common usage patterns. This is suitable for assessments, penetration tests, CTFs, and lab reports.


# 1. Username Enumeration

## Purpose

Identify which usernames exist in the application by analyzing differences in server behavior.

### Common Indicators

| Indicator Type      | Description                                             |
| ------------------- | ------------------------------------------------------- |
| Error Messages      | Different messages for valid and invalid usernames.     |
| Status Codes        | 200 vs 302, 401, or 403 based on user validity.         |
| Response Length     | Valid usernames may produce longer/shorter responses.   |
| Timing Differences  | Real users may trigger database lookups, causing delay. |
| Lockout/Rate Limits | Valid usernames may trigger different rate limits.      |


## Username Enumeration using ffuf

### Command Example (Generic)

```
ffuf -w usernames.txt \
-X POST \
-d "username=FUZZ&password=test" \
-H "Content-Type: application/x-www-form-urlencoded" \
-u http://target/login \
-mr "existing user"
```

### ffuf Flag Reference for Enumeration

| Flag   | Meaning      | Description                                             |
| ------ | ------------ | ------------------------------------------------------- |
| `-w`   | Wordlist     | Provides the list of test usernames.                    |
| `FUZZ` | Fuzz Keyword | Placeholder where ffuf injects each wordlist entry.     |
| `-X`   | HTTP Method  | Controls request type (GET/POST/etc.).                  |
| `-d`   | POST Data    | Form data to send with the request.                     |
| `-H`   | Header       | Allows sending custom headers.                          |
| `-u`   | URL          | Target endpoint.                                        |
| `-mr`  | Match Regex  | Searches response for specific text indicating a match. |


# 2. Password Brute Forcing

## Purpose

Test multiple passwords against one or more usernames when the server does not enforce rate limiting or account lockout.

## General ffuf Brute Force Command

```
ffuf -w usernames.txt:U,passwords.txt:P \
-X POST \
-d "username=U&password=P" \
-H "Content-Type: application/x-www-form-urlencoded" \
-u http://target/login \
-fc 200
```

### ffuf Flags for Brute Force

| Placeholder | Purpose                        |
| ----------- | ------------------------------ |
| `U`         | Username injection placeholder |
| `P`         | Password injection placeholder |

| Flag             | Meaning               | Description                                            |
| ---------------- | --------------------- | ------------------------------------------------------ |
| `-w list1:list2` | Multiple wordlists    | Assigns custom placeholders for multi-field fuzzing.   |
| `-fc`            | Filter by status code | Removes non-interesting HTTP status codes (e.g., 200). |
| `-fw`            | Filter by word count  | Avoids false positives by response length.             |
| `-fs`            | Filter by size        | Filters based on byte length.                          |


# 3. Logic Flaw Authentication Bypass

Logic flaws occur when developers misuse conditions, ignore certain edge cases, or incorrectly validate user identity. These issues allow bypasses without using stolen credentials.

## Common Logic-Break Cases

| Flaw Type                                | Description                                              |
| ---------------------------------------- | -------------------------------------------------------- |
| Case sensitivity issues                  | Paths like /ADMIN vs /admin.                             |
| Missing authorization on secondary steps | E.g., verification enforced only once.                   |
| GET/POST parameter conflicts             | POST overriding GET or vice-versa.                       |
| Insecure redirects                       | Access granted before verifying role.                    |
| Weak workflow logic                      | Multi-step flows assuming previous steps were validated. |

### General Curl-Based Logic Flaw Testing

```
curl http://target/AdMiN
curl http://target/api/admin --path-as-is
curl -X POST http://target/reset -d "step=2&user=test"
```


# 4. Password Reset Exploitation

Password reset functions are commonly misconfigured due to multi-step flows and token handling.

## Typical Weaknesses

| Weakness                   | Explanation                                  |
| -------------------------- | -------------------------------------------- |
| Token not tied to user     | Any valid token works for any account.       |
| Predictable tokens         | Sequential or timestamp-based tokens.        |
| Email override             | Server trusts user-provided email parameter. |
| GET/POST override          | POST values override query parameters.       |
| Weak redirect verification | Reset pages accessible without validation.   |

### General Curl-Based Testing Techniques

| Test                       | Example                                                    |
| -------------------------- | ---------------------------------------------------------- |
| Check for token reuse      | `curl http://target/reset?token=123`                       |
| Override email fields      | `curl -d "email=attacker@example.com" http://target/reset` |
| Bypass step validation     | `curl -d "step=2" http://target/reset`                     |
| Check GET vs POST priority | `curl 'http://target?email=a' -d 'email=b'`                |


# 5. Cookie and Session Manipulation

Cookies often contain session identifiers or privilege indicators. Incorrect validation or weak encoding can lead to privilege escalation.

## Types of Cookie Weaknesses

| Type                    | Description                               |
| ----------------------- | ----------------------------------------- |
| Plaintext flags         | Values like `admin=true`.                 |
| Encoded JSON            | Base64-encoded user roles or IDs.         |
| Unsigned session tokens | Can be modified without server rejection. |
| Predictable session IDs | Can be guessed or enumerated.             |

### General Cookie Manipulation Commands

```
curl -H "Cookie: session=12345" http://target
curl -H "Cookie: admin=true" http://target
```

### Encoding/Decoding

```
echo '{"role":"admin"}' | base64
echo "eyJyb2xlIjoiYWRtaW4ifQ==" | base64 -d
```


# 6. Hashing and Encoding Reference

## Common Hash Algorithms

| Algorithm | Example Output Length | Use Case                 |
| --------- | --------------------- | ------------------------ |
| MD5       | 32 hex chars          | Legacy systems, insecure |
| SHA1      | 40 hex chars          | Deprecated               |
| SHA256    | 64 hex chars          | Modern hashing           |
| SHA512    | 128 hex chars         | High security            |

### Generate Hash via CLI

```
echo -n "text" | md5sum
echo -n "text" | sha256sum
```

## Common Encodings

| Encoding     | Purpose                 | Reversible |
| ------------ | ----------------------- | ---------- |
| Base64       | Data transport          | Yes        |
| URL Encoding | Safe HTTP transfer      | Yes        |
| Hex Encoding | Lower-level data format | Yes        |


# 7. Curl Command Cheat Sheet

| Purpose                    | Command                                                  |
| -------------------------- | -------------------------------------------------------- |
| Basic GET                  | `curl http://target`                                     |
| POST Form Submission       | `curl -X POST -d "a=1&b=2" http://target`                |
| Add Headers                | `curl -H "Content-Type: application/json" http://target` |
| Add Cookies                | `curl -H "Cookie: session=123" http://target`            |
| Show Full Request/Response | `curl -v http://target`                                  |
| Follow Redirects           | `curl -L http://target`                                  |


# 8. ffuf Cheat Sheet (General)

| Purpose               | Example                                            |
| --------------------- | -------------------------------------------------- |
| Directory brute force | `ffuf -w dirs.txt -u http://target/FUZZ`           |
| Subdomain brute force | `ffuf -w subs.txt -u http://FUZZ.target`           |
| Parameter fuzzing     | `ffuf -w params.txt -u http://target/?FUZZ=1`      |
| POST fuzzing          | `ffuf -X POST -d "user=FUZZ" -u http://target`     |
| Multiple wordlists    | `ffuf -w list1:A,list2:B -u http://target?u=A&p=B` |
| Filter status codes   | `-fc 404`                                          |
| Filter response size  | `-fs 1000`                                         |
| Match specific text   | `-mr "success"`                                    |


# 9. Authentication Bypass Testing Checklist

1. Test for username enumeration.
2. Check if the login page leaks specific messages.
3. Attempt brute force or password spraying.
4. Inspect all multi-step workflows.
5. Test for case-sensitivity issues.
6. Attempt GET vs POST parameter override.
7. Inspect cookies for weak privilege flags.
8. Base64 decode all non-random cookie strings.
9. Attempt direct access to admin or internal endpoints.
10. Test for path manipulations such as double slashes, mixed case, or trailing slashes.
11. Evaluate password reset tokens for predictability or misuse.
12. Check whether session tokens can be modified.


