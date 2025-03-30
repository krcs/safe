# Stand-Alone File Encryptor (safe)

Safe is a command-line tool for file encryption/decryption.

## Installation
Requires [Go](https://golang.org/) 1.16+.

Build:

      go build -o safe safe.go

Run:

      go run safe.go

## Usage

     Usage: safe <command> [flags]

    Commands:
      encrypt -i <input file> -o <output file> [-p <password>]
      decrypt -i <input file> -o <output file> [-p <password>]

    Global Flags:
      -h, --help       Show this help information
      -v, --version    Show version information

    Command Flags:
      -i, --input      Input file
      -o, --output     Output file
      -p, --password
      -vp, --verify    Confirm password if it is entered through the standard input.
                       Ignored when the -p flag is specified.

### Examples

Encrypt:

      safe encrypt -i file.txt -o file.enc -p "password"

Decrypt:

      safe decrypt -i file.enc -o file.dec -p "password"

## Cryptography
- **Encryption**: XChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305`) – 256-bit key, 24-byte random nonce.
- **Key Derivation**: Argon2id (`golang.org/x/crypto/argon2`) – 256MB (encrypt) / 128MB (HMAC), 32-byte output.
- **Integrity**: HMAC-SHA3-512 (`golang.org/x/crypto/sha3`, `crypto/hmac`) – 512-bit output.
- **Randomness**: `crypto/rand` for nonces, salts, padding (0-64 bytes/chunk).
- **Features**: 64KB chunks, quantum-resistant, constant-time HMAC checks (`crypto/subtle`).
