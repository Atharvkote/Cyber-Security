<p align="center">
    <img src="../.git-config/John.webp" alt="img">
</p>

# Hash Identification and Password Cracking with John the Ripper in Kali Linux

## 1. Introduction

This guide explains how to:

* Install and use **hash-identifier** to detect the type of a hash.
* Prepare and use a wordlist (rockyou.txt) in Kali Linux.
* Crack the identified hash using **John the Ripper**.
* Crack Windows password hashes (NTLM format).
* Crack Linux user passwords from `/etc/shadow`.

The process is demonstrated with MD5, NTLM, and Linux password hashes.

## 2. Installing hash-identifier

**hash-identifier** is a Python-based tool that attempts to detect the type of a given hash string. It is available in the Kali Linux repositories.

Update package lists:

```bash
sudo apt update
```

Install the tool:

```bash
sudo apt install hash-identifier
```

Verify installation:

```bash
hash-identifier
```

Alternatively, if the package is missing, download it manually:

```bash
wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py -O hash-id.py
chmod +x hash-id.py
python3 hash-id.py
```

## 3. Identifying the Hash Type

Start **hash-identifier**:

```bash
hash-identifier
```

When prompted, paste the hash string.
Example:

```
5d41402abc4b2a76b9719d911017c592
```

The tool will output possible hash types. In this case, it identifies the hash as MD5 among other possible algorithms.

## 4. Creating a Hash File for Cracking

Save the hash into a file to make it easier to use with John the Ripper:

```bash
echo "5d41402abc4b2a76b9719d911017c592" > hash.txt
```

You can also create it manually:

```bash
touch hash.txt
nano hash.txt
```

Paste the hash and save the file.

## 5. Preparing the Wordlist

**John the Ripper** uses wordlists to attempt password cracking. Kali includes the `rockyou.txt` wordlist in compressed form at:

```
/usr/share/wordlists/rockyou.txt.gz
```

Unzip it (only required once):

```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

This will produce:

```
/usr/share/wordlists/rockyou.txt
```

## 6. Cracking the Password with John the Ripper

To crack the MD5 hash using the uncompressed wordlist:

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

John will load the hash and start comparing it with each password in the wordlist.

## 7. Viewing the Cracked Password

Once John finishes or finds a match, display the cracked password:

```bash
john --show --format=raw-md5 hash.txt
```

For the example hash `5d41402abc4b2a76b9719d911017c592`, the password is:

```
hello
```

## 8. Cracking Windows Passwords (NTLM Hashes)

Windows password hashes are stored in the **SAM** (Security Account Manager) database, typically located in:

```
C:\Windows\System32\config\SAM
```

and require the **SYSTEM** file for extraction.

### 8.1 Extracting NTLM Hashes

If you have a copy of the SAM and SYSTEM files, you can extract NTLM hashes using **impacket-secretsdump**:

```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

The output will include lines in the format:

```
username:RID:LMhash:NThash:::
```

Example NTLM hash:

```
aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

### 8.2 Cracking NTLM Hashes

Save the NTLM hash into a file:

```bash
echo "8846f7eaee8fb117ad06bdd830b7586c" > ntlm.txt
```

Run John with NTLM format:

```bash
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
```

View results:

```bash
john --show --format=NT ntlm.txt
```

## 9. Cracking Linux User Passwords from `/etc/shadow`

Linux user account hashes are stored in `/etc/shadow` and require root privileges to read.
The `/etc/passwd` file contains usernames and related info, while `/etc/shadow` contains the actual hashes.

### 9.1 Extracting the Hash

To view `/etc/shadow`:

```bash
sudo cat /etc/shadow
```

Example line:

```
root:$6$gZ8KcU2.$8kkv0f8B.3Cb7dlCF4A1jYz/ZgWfnXc0lRYiAhe5kITsF2DrfpbtDk4h0bADFbFyjHdFm5n2JpQfK4fq1u4nT.:19751:0:99999:7:::
```

Here, `$6$` indicates SHA-512 hashing.

### 9.2 Cracking the Hash

Save the entire line into a file:

```bash
sudo unshadow /etc/passwd /etc/shadow > linux_hashes.txt
```

Run John with SHA-512 format:

```bash
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt linux_hashes.txt
```

Show cracked passwords:

```bash
john --show --format=sha512crypt linux_hashes.txt
```

## 10. Notes and Best Practices

* Accessing `/etc/shadow` or Windows SAM files requires administrative/root privileges.
* Always perform password cracking on systems you own or have explicit permission to test.
* Different hash formats require specific `--format` options in John.
* Large wordlists improve success rates but take more time to process.

