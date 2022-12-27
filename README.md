# Vault

> A simple CLI based document encryption/decryption using a only a password.

## Usage

```bash 
$ ./vault close <file> --retain-source  # Encrypts a file without removing it afterwards
$ ./vault open <file> --retain-source   # Decrypts a file without removing it afterwards
```

You can verify that the file is indeed the same after encryption and subsequent decryption by running `shasum` on the original and the decrypted file.