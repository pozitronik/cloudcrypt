# CloudCrypt

Standalone command-line utility for encrypting and decrypting files using the same cipher backends as the [https://github.com/pozitronik/CloudMailRu](CloudMailRu Total Commander plugin). Useful for backup verification, migration between storage providers, or working with encrypted files outside Total Commander.

## Building

### Prerequisites

- Embarcadero Delphi (RAD Studio) with Win64 target support

## Usage

```
CloudCrypt <command> [options]
```

### Commands

| Command    | Description                          |
|------------|--------------------------------------|
| `encrypt`  | Encrypt file(s) or directory         |
| `decrypt`  | Decrypt file(s) or directory         |
| `profiles` | List available cipher profiles       |
| `help`     | Show usage information               |

### Options

| Option          | Description                                              |
|-----------------|----------------------------------------------------------|
| `-in <path>`    | Input file or directory                                  |
| `-out <path>`   | Output file or directory (must differ from input)        |
| `-p <password>` | Encryption password (prompted interactively if omitted)  |
| `-profile <id>` | Cipher profile ID (default: `dcpcrypt-aes256-cfb8-sha1`) |

### Examples

Encrypt a single file:
```
CloudCrypt encrypt -in document.pdf -out document.pdf.enc -p mypassword
```

Decrypt a single file:
```
CloudCrypt decrypt -in document.pdf.enc -out document.pdf -p mypassword
```

Encrypt an entire directory (recursive):
```
CloudCrypt encrypt -in C:\MyFiles -out D:\Encrypted -p mypassword
```

Decrypt with a specific cipher profile:
```
CloudCrypt decrypt -in backup.enc -out backup.dat -p mypassword -profile bcrypt-aes256-cfb8-pbkdf2
```

Interactive password prompt (no `-p` flag):
```
CloudCrypt encrypt -in secret.doc -out secret.doc.enc
Enter password: ****
```

List available cipher profiles:
```
CloudCrypt profiles
```

## Cipher Profiles

CloudCrypt supports the same cipher backends as the main plugin:

| Profile ID                        | Backend     | Algorithm   | KDF     |
|-----------------------------------|-------------|-------------|---------|
| `dcpcrypt-aes256-cfb8-sha1`       | DCPCrypt    | AES-256     | SHA-1   |
| `dcpcrypt-aes256-cfb8-sha256`     | DCPCrypt    | AES-256     | SHA-256 |
| `dcpcrypt-twofish256-cfb8-sha256` | DCPCrypt    | Twofish-256 | SHA-256 |
| `openssl-aes256-cfb8-pbkdf2`      | OpenSSL     | AES-256     | PBKDF2  |
| `bcrypt-aes256-cfb8-pbkdf2`       | Windows CNG | AES-256     | PBKDF2  |

The default profile (`dcpcrypt-aes256-cfb8-sha1`) is the legacy profile used by most existing encrypted files in CloudMailRu.

OpenSSL profiles require `libcrypto-*.dll` on the system PATH. BCrypt profiles use Windows CNG and are available on Vista and later. If a backend is not available, its profiles will not appear in the `profiles` listing.

## Technical Details

### CFB-8 Stream Cipher

All profiles use CFB-8 (Cipher Feedback with 8-bit shift register) mode. Key properties:

- **No size change**: encrypted file is exactly the same size as the original (no headers, padding, or metadata)
- **No password validation**: decrypting with the wrong password silently produces garbage rather than returning an error. This matches the plugin behavior.
- **No in-place operation**: input and output paths must differ because CFB-8 reads and writes sequentially

### Compatibility

Files encrypted by the [https://github.com/pozitronik/CloudMailRu](CloudMailRu plugin) can be decrypted by CloudCrypt and vice versa, provided the same profile and password are used. The default profile matches the plugin's default encryption settings.

### Directory Mode

When `-in` points to a directory:
- All files are processed recursively
- The directory structure is replicated under `-out`
- Individual file failures do not stop processing of remaining files
- A summary of processed/failed counts is printed at the end

## Exit Codes

| Code | Meaning                               |
|------|---------------------------------------|
| 0    | Success (all files processed)         |
| 1    | Invalid arguments or help display     |
| 2    | Password not provided                 |
| 3    | Unknown cipher profile                |
| 4    | Input path does not exist             |
| 5    | One or more files failed              |

## Testing

Unit tests for the core logic are in `tests/CloudCryptCoreTest.pas` and run as a separate test project:

```
tools\CloudCrypt\test.bat
```

Output: `tools\CloudCrypt\tests\Win64\Debug\CloudCryptTest.exe`

Test coverage includes argument parsing, input validation, single-file and directory encryption/decryption roundtrips, cross-profile verification, and error handling.

# Licence
GNU GPL v3.0