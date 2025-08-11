![img](../.git-config/John.webp)

# Hash Identification and Password Cracking with John the Ripper in Kali Linux

## 1. Introduction

This guide explains how to:

* Install and use **hash-identifier** to detect the type of a hash.
* Prepare and use a wordlist (rockyou.txt) in Kali Linux.
* Crack the identified hash using **John the Ripper**.

The process is demonstrated using an MD5 hash as an example.

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

## 8. Notes and Best Practices

* The accuracy of hash identification is not guaranteed if multiple algorithms produce hashes with the same format and length.
* Use the correct `--format` in John the Ripper. For example:

  * `raw-md5` for standard MD5 hashes.
  * `raw-sha1` for SHA1.
  * `bcrypt` for bcrypt hashes.
* Large wordlists increase the likelihood of cracking passwords but also increase the runtime.
* Always have permission to test hashes. Unauthorized cracking is illegal.
