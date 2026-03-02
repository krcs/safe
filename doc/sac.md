# SAC — Secure Authenticated Cipher

A file-encryption library written in Go that provides confidentiality, integrity, and authenticity for arbitrary files using modern cryptographic primitives.

---

## Table of Contents

1. [Overview](#overview)
2. [Cryptographic Primitives](#cryptographic-primitives)
3. [Key Derivation](#key-derivation)
4. [File Format](#file-format)
5. [Encryption — Step by Step](#encryption--step-by-step)
6. [Decryption — Step by Step](#decryption--step-by-step)
7. [Security Properties](#security-properties)
8. [Constants and Parameters](#constants-and-parameters)
9. [API Reference](#api-reference)
10. [Usage Example](#usage-example)
11. [Test Suite](#test-suite)

---

## Overview

SAC encrypts a file by:

1. Deriving four independent cryptographic keys from the user's password using **Argon2id**.
2. Encrypting a metadata header with one key.
3. Splitting the plaintext into **64 KB chunks**, encrypting each chunk independently with **XChaCha20-Poly1305** and authenticating it with its position in the file.
4. Appending a file-level **SHA3-512 HMAC** over all ciphertext chunks to detect truncation, extension, and reordering across chunks.

Every error path that can indicate a wrong password or file tampering returns the single opaque string `"decryption failed"` — no information is leaked about which check failed.

---

## Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|---|---|---|
| Key derivation | Argon2id | Derive all keys from the password |
| Data encryption | XChaCha20-Poly1305 | Authenticated encryption of each chunk and the header |
| File integrity | SHA3-512 HMAC | Authenticate the complete ciphertext stream |
| Randomness | `crypto/rand` | All nonces, salts, domain separators, and padding |

### Why these choices?

**Argon2id** is the winner of the Password Hashing Competition (2015) and is the current NIST-recommended algorithm for password-based key derivation. The `id` variant combines the side-channel resistance of Argon2i with the GPU-resistance of Argon2d.

**XChaCha20-Poly1305** (the 192-bit nonce variant of ChaCha20-Poly1305) allows large random nonces, eliminating nonce-reuse risk even when many files are encrypted with the same key. It is used in TLS 1.3, WireGuard, and Signal.

**SHA3-512 HMAC** provides a file-level integrity check that is independent of the per-chunk AEAD tags. This catches attacks that rearrange or remove entire chunks — attacks that the per-chunk AEAD alone cannot detect.

---

## Key Derivation

The password is never used directly as a cryptographic key. Instead, four independent 256-bit keys are derived from it using Argon2id, each with its own unique salt and domain separator stored in the encrypted file header.

```
password ──┬──► Argon2id(salt=Salt║EncDomainSep,   iter=10, mem=256MB) ──► encKey       (data encryption)
           ├──► Argon2id(salt=HMACSalt║HMACDomainSep, iter=3,  mem=128MB) ──► headerHmacKey (header MAC)
           ├──► Argon2id(salt=FileHMACSalt║FileDomainSep, iter=3, mem=128MB) ──► fileHmacKey  (file MAC)
           └──► Argon2id(salt=headerDomainSep║headerSalt, iter=10, mem=256MB) ──► headerKey    (header encryption)
```

**Key separation** is enforced at three levels:

1. **Different salts** — each KDF call uses a distinct random salt stored in the file.
2. **Different domain separators** — a random tag prepended to the salt ensures that even with the same password and salt, the four keys are different.
3. **Different KDF parameters** — encryption and header keys use stronger parameters (`iter=10, mem=256 MB`) than HMAC keys (`iter=3, mem=128 MB`), reflecting their different roles.

---

## File Format

An encrypted file is a sequential byte stream with no padding between sections. All multi-byte integers are big-endian.

```
┌─────────────────────────────────────────────────────────────────┐
│ PREAMBLE (plaintext — used to derive headerKey)                 │
│   headerDomainSeparator       16 bytes                          │
│   headerSalt                  32 bytes                          │
├─────────────────────────────────────────────────────────────────┤
│ HEADER BLOCK                                                    │
│   headerNonce                 24 bytes                          │
│   encryptedHeader             205 bytes  (189 + 16 AEAD tag)   │
│   headerHMAC                  64 bytes                          │
├─────────────────────────────────────────────────────────────────┤
│ CHUNK 0                                                         │
│   nonce₀                      24 bytes                          │
│   chunkAD₀                     5 bytes  (paddingSize║index)     │
│   ciphertext₀             up to 65,552 bytes  (64KB + 16 tag)  │
│   padding₀                  0–63 bytes  (random)               │
├─────────────────────────────────────────────────────────────────┤
│ CHUNK 1 … CHUNK N                                               │
│   (same layout as CHUNK 0)                                      │
├─────────────────────────────────────────────────────────────────┤
│ FILE HMAC                     64 bytes  (SHA3-512)              │
└─────────────────────────────────────────────────────────────────┘
```

**Minimum file size** (empty input): 405 bytes.

### FileHeader struct (189 bytes, binary big-endian)

| Field | Size | Description |
|---|---|---|
| `Version` | 1 byte | File format version (currently `1`) |
| `Salt` | 32 bytes | Salt for `encKey` derivation |
| `HMACSalt` | 32 bytes | Salt for `headerHmacKey` derivation |
| `FileHMACSalt` | 32 bytes | Salt for `fileHmacKey` derivation |
| `HMACIV` | 32 bytes | Initial value fed into `fileMac` |
| `HMACDomainSeparator` | 16 bytes | Domain separator for `headerHmacKey` |
| `FileHMACDomainSeparator` | 16 bytes | Domain separator for `fileHmacKey` |
| `EncDomainSeparator` | 16 bytes | Domain separator for `encKey` |
| `PaddingLength` | 4 bytes | Total random padding bytes across all chunks |
| `DataLength` | 8 bytes | Total plaintext length in bytes |

### Chunk additional data (5 bytes)

Each chunk's AEAD additional data encodes two fields that bind the ciphertext to its position and padding size:

```
byte 0:     paddingSize   (0–63, how many padding bytes follow this chunk's ciphertext)
bytes 1–4:  chunkIndex    (uint32, big-endian, 0-based position in the file)
```

This prevents an attacker from reordering chunks or duplicating a chunk, because AEAD authentication would fail with the wrong `chunkIndex` in the additional data.

---

## Encryption — Step by Step

Below is a worked example for a 90 KB plaintext file (`secret.txt`) encrypted with the password `"hunter2"`, producing `secret.txt.sac`.

### Step 1 — Validate inputs

```
checkDistinctPaths("secret.txt", "secret.txt.sac")  → OK
os.Open("secret.txt")                               → inFile
inFile.Stat().Size() = 92,160 bytes (90 KB)         → within 256 GB limit
```

### Step 2 — Generate the FileHeader

`GenerateHeader()` fills the struct with cryptographically random values:

```
header.Version                 = 1
header.Salt                    = [32 random bytes]  e.g. a3 f1 8c ...
header.HMACSalt                = [32 random bytes]  e.g. 7b 44 02 ...
header.FileHMACSalt            = [32 random bytes]  e.g. c9 81 5e ...
header.HMACIV                  = [32 random bytes]  e.g. 3d 09 ff ...
header.HMACDomainSeparator     = [16 random bytes]
header.FileHMACDomainSeparator = [16 random bytes]
header.EncDomainSeparator      = [16 random bytes]
header.DataLength              = 0   (filled in later)
header.PaddingLength           = 0   (filled in later)
```

### Step 3 — Generate the preamble and derive all keys

```
headerDomainSeparator = [16 random bytes]   written to file as plaintext
headerSalt            = [32 random bytes]   written to file as plaintext

encKey        = Argon2id(password, Salt║EncDomainSeparator,   iter=10, mem=256MB, t=4, len=32)
headerHmacKey = Argon2id(password, HMACSalt║HMACDomainSep,    iter=3,  mem=128MB, t=4, len=32)
fileHmacKey   = Argon2id(password, FileHMACSalt║FileDomainSep, iter=3,  mem=128MB, t=4, len=32)
headerKey     = Argon2id(password, headerDomainSep║headerSalt, iter=10, mem=256MB, t=4, len=32)
```

Each Argon2id call processes the password with a unique salt. Two callers with the same password but different random salts will always get different keys.

### Step 4 — Write the preamble

```
outFile.Write(headerDomainSeparator)   // 16 bytes — plaintext
outFile.Write(headerSalt)              // 32 bytes — plaintext
```

**File so far:** 48 bytes

### Step 5 — Write a placeholder header

The final `DataLength` and `PaddingLength` are unknown until all chunks are processed, so a placeholder header (with both fields set to `0`) is written now. The file offset of this block is recorded so the header can be overwritten later.

```
headerOffset = 48   (byte position of the nonce that starts the header block)

writeHeader(placeholder):
  headerNonce  = [24 random bytes]
  plainHeader  = binary.BigEndian(header)          // 189 bytes
  encHeader    = XChaCha20-Poly1305.Seal(plainHeader, nonce=headerNonce)  // 205 bytes
  headerHMAC   = HMAC-SHA3-512(header, key=headerHmacKey)                 // 64 bytes

  outFile.Write(headerNonce)   // 24 bytes
  outFile.Write(encHeader)     // 205 bytes
  outFile.Write(headerHMAC)    // 64 bytes
```

**File so far:** 48 + 24 + 205 + 64 = **341 bytes**

### Step 6 — Initialise the file HMAC

```
fileMac = HMAC-SHA3-512(key=fileHmacKey)
fileMac.Write(header.HMACIV)   // seed with the 32-byte HMACIV
```

### Step 7 — Encrypt chunks

The 90 KB file (92,160 bytes) is split into two chunks:

- **Chunk 0:** 65,536 bytes (exactly 64 KB)
- **Chunk 1:** 26,624 bytes (remaining 26 KB)

#### Chunk 0

```
n = io.ReadFull(inFile, buf)   // n = 65,536 bytes
data = buf[:65536]

nonce₀       = [24 random bytes]
paddingSize₀ = rand.Read(1)[0] % 64  → e.g. 37
padding₀     = [37 random bytes]

header.DataLength    += 65536   → 65,536
header.PaddingLength += 37      → 37

chunkAD₀ = [paddingSize=37, chunkIndex=0]  // 5 bytes: 0x25 0x00 0x00 0x00 0x00

ciphertext₀ = XChaCha20-Poly1305.Seal(
    plaintext = data,             // 65,536 bytes
    nonce     = nonce₀,          // 24 bytes
    aad       = chunkAD₀,        // 5 bytes — authenticated, not encrypted
)
// ciphertext₀ length = 65,536 + 16 (Poly1305 tag) = 65,552 bytes

outFile.Write(nonce₀)        // 24 bytes
outFile.Write(chunkAD₀)      //  5 bytes
outFile.Write(ciphertext₀)   // 65,552 bytes
outFile.Write(padding₀)      // 37 bytes

fileMac.Write(nonce₀)
fileMac.Write(chunkAD₀)
fileMac.Write(ciphertext₀)

zeroBytes(nonce₀)       // wipe from memory immediately
zeroBytes(ciphertext₀)  // wipe from memory immediately
```

**File so far:** 341 + 24 + 5 + 65,552 + 37 = **65,959 bytes**

#### Chunk 1

```
n = io.ReadFull(inFile, buf)   // n = 26,624 bytes (io.ErrUnexpectedEOF — last chunk)
data = buf[:26624]

nonce₁       = [24 random bytes]
paddingSize₁ = rand.Read(1)[0] % 64  → e.g. 12
padding₁     = [12 random bytes]

header.DataLength    += 26624   → 92,160
header.PaddingLength += 12      → 49

chunkAD₁ = [paddingSize=12, chunkIndex=1]  // 5 bytes: 0x0c 0x00 0x00 0x00 0x01

ciphertext₁ = XChaCha20-Poly1305.Seal(
    plaintext = data,    // 26,624 bytes
    nonce     = nonce₁,
    aad       = chunkAD₁,
)
// ciphertext₁ length = 26,624 + 16 = 26,640 bytes

outFile.Write(nonce₁)        // 24 bytes
outFile.Write(chunkAD₁)      //  5 bytes
outFile.Write(ciphertext₁)   // 26,640 bytes
outFile.Write(padding₁)      // 12 bytes

fileMac.Write(nonce₁)
fileMac.Write(chunkAD₁)
fileMac.Write(ciphertext₁)

zeroBytes(nonce₁)
zeroBytes(ciphertext₁)
```

**File so far:** 65,959 + 24 + 5 + 26,640 + 12 = **92,640 bytes**

### Step 8 — Rewrite the header with final values

Now that `DataLength` and `PaddingLength` are known, seek back to `headerOffset` and overwrite the placeholder:

```
header.DataLength    = 92,160
header.PaddingLength = 49

outFile.Seek(48, SeekStart)   // jump back to the header block
writeHeader(final):           // uses a FRESH nonce — never reuses the placeholder's nonce
  headerNonce₂ = [24 new random bytes]
  encHeader₂   = XChaCha20-Poly1305.Seal(binary.BigEndian(header), nonce=headerNonce₂)
  headerHMAC₂  = HMAC-SHA3-512(header, key=headerHmacKey)

  outFile.Write(headerNonce₂)  // overwrites bytes 48–71
  outFile.Write(encHeader₂)    // overwrites bytes 72–276
  outFile.Write(headerHMAC₂)   // overwrites bytes 277–340

outFile.Seek(0, SeekEnd)      // jump to end of file
```

Using a fresh nonce on the rewrite means the two header writes — placeholder and final — use completely different nonces, preventing any nonce-reuse vulnerability.

### Step 9 — Append the file HMAC

```
fileHmac = fileMac.Sum()   // 64 bytes of SHA3-512 HMAC
outFile.Write(fileHmac)
zeroBytes(fileHmac)        // wipe from memory immediately
```

**Final file size:** 92,640 + 64 = **92,704 bytes**

### Final file layout (our 90 KB example)

```
Offset      Length    Content
──────────────────────────────────────────────────────────────────
0           16        headerDomainSeparator (plaintext)
16          32        headerSalt (plaintext)
48          24        headerNonce₂ (final nonce)
72          205       encryptedHeader (XChaCha20-Poly1305)
277         64        headerHMAC (HMAC-SHA3-512)
341         24        nonce₀
365          5        chunkAD₀  (paddingSize=37, index=0)
370         65,552    ciphertext₀ (XChaCha20-Poly1305)
65,922      37        padding₀
65,959      24        nonce₁
65,983       5        chunkAD₁  (paddingSize=12, index=1)
65,988      26,640    ciphertext₁ (XChaCha20-Poly1305)
92,628      12        padding₁
92,640      64        fileHMAC (HMAC-SHA3-512)
──────────────────────────────────────────────────────────────────
Total:      92,704 bytes
```

---

## Decryption — Step by Step

Decryption is the exact inverse of encryption, with all integrity checks performed **before** any plaintext is written to disk. If any check fails, the output file is deleted and `"decryption failed"` is returned.

### Step 1 — Size guard

```
headerSize = 16 + 32 + 24 + 205 + 64 + 64 = 405 bytes

if fileSize < headerSize  → "decryption failed"  (too small to be valid)
if fileSize > 256GB + 405 → "decryption failed"  (too large)
```

### Step 2 — Read the preamble and derive `headerKey`

```
headerDomainSeparator = read 16 bytes
headerSalt            = read 32 bytes

headerKey = Argon2id(password, headerDomainSeparator║headerSalt, iter=10, mem=256MB)

zeroBytes(headerDomainSeparator)   // wipe KDF inputs immediately
zeroBytes(headerSalt)
```

### Step 3 — Decrypt and authenticate the header

```
headerNonce     = read 24 bytes
encryptedHeader = read 205 bytes
storedHeaderHmac = read 64 bytes

header = XChaCha20-Poly1305.Open(encryptedHeader, nonce=headerNonce)
  // if AEAD tag fails → "decryption failed"
```

### Step 4 — Derive the remaining keys and verify the header HMAC

```
encKey        = Argon2id(password, header.Salt║header.EncDomainSeparator,   iter=10, mem=256MB)
headerHmacKey = Argon2id(password, header.HMACSalt║header.HMACDomainSep,    iter=3,  mem=128MB)
fileHmacKey   = Argon2id(password, header.FileHMACSalt║header.FileDomainSep, iter=3,  mem=128MB)

computedHmac = HMAC-SHA3-512(header, key=headerHmacKey)
if computedHmac ≠ storedHeaderHmac → "decryption failed"
  // constant-time comparison

zeroBytes(computedHmac)

if header.Version ≠ 1          → "decryption failed"
if header.DataLength > 256 GB  → "decryption failed"
```

### Step 5 — Initialise the file HMAC and prepare the output

```
fileMac = HMAC-SHA3-512(key=fileHmacKey)
fileMac.Write(header.HMACIV)

outFile = os.Create(outputPath)
  // if decryption fails at any later point, outFile is deleted
```

### Step 6 — Decrypt chunks

For each chunk (loop continues while `encryptedSize > 0 && remainingData > 0`):

```
nonce     = read 24 bytes
chunkAD   = read 5 bytes
  paddingSize = chunkAD[0]
  chunkIndex  = BigEndian.Uint32(chunkAD[1:])

if chunkIndex ≠ expectedChunkIndex → "decryption failed"  // reorder/replay check

cipherSize = min(remainingData, 64KB) + 16

ciphertext = read cipherSize bytes

fileMac.Write(nonce)
fileMac.Write(chunkAD)
fileMac.Write(ciphertext)

plaintext = XChaCha20-Poly1305.Open(ciphertext, nonce=nonce, aad=chunkAD)
  // if AEAD tag fails → "decryption failed"

outFile.Write(plaintext)
zeroBytes(plaintext)    // wipe immediately

if paddingSize > 0:
  read and discard paddingSize bytes

expectedChunkIndex++
```

### Step 7 — Verify no trailing data

```
if encryptedSize ≠ 0 → "decryption failed"
  // catches file extension attacks
```

### Step 8 — Verify the file HMAC

```
storedHmac   = read last 64 bytes
computedHmac = fileMac.Sum()

if computedHmac ≠ storedHmac → "decryption failed"
  // constant-time comparison
zeroBytes(computedHmac)
```

Only if all checks pass is `succeeded = true` set, preventing the defer from deleting the output file.

---

## Security Properties

| Property | How it is achieved |
|---|---|
| **Confidentiality** | XChaCha20-Poly1305 with a unique random nonce per chunk |
| **Integrity** | Poly1305 tag per chunk + SHA3-512 file HMAC |
| **Authenticity** | Encrypt-then-MAC; both MACs require the correct password |
| **Semantic security** | Fresh random nonces and salts on every encryption |
| **Chunk ordering** | `chunkIndex` in AEAD additional data; out-of-order → AEAD failure |
| **Truncation detection** | File HMAC covers all chunks; `encryptedSize == 0` post-loop check |
| **Extension detection** | `encryptedSize == 0` check after the decryption loop |
| **Header integrity** | Header HMAC with an independent key (`headerHmacKey`) |
| **Key separation** | Four independent Argon2id derivations with different salts and domain separators |
| **Password hardening** | Argon2id with 256 MB memory, 10 iterations, 4 threads |
| **Memory hygiene** | All key material zeroed via `subtle.ConstantTimeCopy` immediately after use |
| **No partial output** | Failed encrypt or decrypt deletes the output file |
| **No oracle** | All failure paths return `"decryption failed"` |
| **No TOCTOU race** | `os.Open` then `fd.Stat()` — file stat taken on the open descriptor |
| **Same-path guard** | `os.SameFile` prevents encrypting a file over itself |

---

## Constants and Parameters

### Argon2id parameters (configurable via package variables)

| Variable | Default | Role |
|---|---|---|
| `Iterations` | `10` | Time cost for `encKey` and `headerKey` |
| `Memory` | `256 MB` | Memory cost for `encKey` and `headerKey` |
| `HmacIter` | `3` | Time cost for `headerHmacKey` and `fileHmacKey` |
| `HmacMemory` | `128 MB` | Memory cost for `headerHmacKey` and `fileHmacKey` |
| `Threads` | `4` | Parallelism (all four KDF calls) |

These are package-level `var` declarations (not constants) so they can be overridden in tests without modifying source code.

### File format constants

| Constant | Value | Description |
|---|---|---|
| `Version` | `1` | File format version number |
| `ChunkSize` | `65,536` | Plaintext bytes per chunk |
| `NonceSize` | `24` | XChaCha20 nonce size |
| `KeySize` | `32` | 256-bit AES-equivalent key size |
| `SaltSize` | `32` | Argon2 salt size |
| `HmacSaltSize` | `32` | Argon2 salt size for HMAC keys |
| `HmacIVSize` | `32` | File HMAC initial value |
| `HmacSize` | `64` | SHA3-512 output size |
| `HeaderHmacSize` | `64` | Header HMAC size |
| `HeaderNonceSize` | `24` | Header encryption nonce |
| `HeaderSaltSize` | `32` | Salt for `headerKey` |
| `HeaderDomainSeparator` | `16` | Domain separator for `headerKey` |
| `DomainSeparatorSize` | `16` | Domain separator size for all other keys |
| `MaxPaddingSize` | `64` | Maximum random padding bytes per chunk |
| `MaxFileSize` | `256 GB` | Maximum plaintext size |
| `ChunkADSize` | `5` | Bytes of AEAD additional data per chunk |

---

## API Reference

### `EncryptFile(password []byte, inputPath, outputPath string) error`

Encrypts the file at `inputPath`, writing the result to `outputPath`.

- `password` is zeroed from memory before the function returns regardless of outcome.
- `outputPath` is deleted if encryption fails at any point.
- `inputPath` and `outputPath` must not refer to the same filesystem object.
- Returns a descriptive error (not `"decryption failed"`) on infrastructure failures (file not found, disk full, etc.).

### `DecryptFile(password []byte, inputPath, outputPath string) error`

Decrypts the file at `inputPath`, writing the result to `outputPath`.

- `password` is zeroed from memory before the function returns regardless of outcome.
- `outputPath` is deleted if decryption fails or any integrity check does not pass.
- Returns `"decryption failed"` for any cryptographic failure (wrong password, corrupted file, tampered data, etc.).

### `ComputeHeaderHMAC(header FileHeader, hmacKey []byte) ([]byte, error)`

Returns the 64-byte SHA3-512 HMAC over the canonical big-endian binary serialisation of `header`. Exported to allow external format verification tools.

### `GenerateHeader() (FileHeader, error)`

Generates a `FileHeader` with all random fields populated. Used internally by `EncryptFile`; exported for testing and tooling.

### `GenerateRandomBytes(n uint) ([]byte, error)`

Returns `n` cryptographically random bytes from `crypto/rand`.

---

## Usage Example

```go
package main

import (
    "fmt"
    "os"

    "yourmodule/sac"
)

func main() {
    password := []byte("correct horse battery staple")

    // Encrypt
    err := sac.EncryptFile(
        password,          // zeroed on return
        "secret.txt",      // input
        "secret.txt.sac",  // output
    )
    if err != nil {
        fmt.Fprintln(os.Stderr, "encrypt:", err)
        os.Exit(1)
    }
    fmt.Println("Encrypted successfully.")

    // Decrypt
    err = sac.DecryptFile(
        []byte("correct horse battery staple"),
        "secret.txt.sac",
        "secret.txt.dec",
    )
    if err != nil {
        // err is always "decryption failed" for wrong password / tampered file
        fmt.Fprintln(os.Stderr, "decrypt:", err)
        os.Exit(1)
    }
    fmt.Println("Decrypted successfully.")
}
```

> **Note:** `EncryptFile` and `DecryptFile` zero the `password` slice before returning. If you need the password afterwards, pass a copy: `append([]byte(nil), password...)`.

---

## Test Suite

The package includes a comprehensive test suite in `sac_test.go` covering five categories:

### 1. Functional correctness
Roundtrip tests for empty files, small files, files at exactly the chunk boundary (64 KB − 1, 64 KB, 64 KB + 1), multi-chunk files, binary data, all-zero plaintext, and unicode passwords.

### 2. Cryptographic properties

| Test | What it verifies |
|---|---|
| `TestNonDeterminism` | Two encryptions of the same plaintext produce different ciphertexts |
| `TestTamper_SingleBitFlip` | Flipping one bit in the payload causes decryption to fail |
| `TestTamper_LastByte` | Corrupting the file HMAC causes failure |
| `TestTamper_HeaderCorruption` | Corrupting the encrypted header causes failure |
| `TestTamper_HeaderHMAC` | Corrupting the header HMAC causes failure |
| `TestTamper_FileHMAC` | Corrupting the file HMAC causes failure |
| `TestTamper_Truncation` | Removing bytes from the end causes failure |
| `TestTamper_Extension` | Appending bytes after the last chunk causes failure |

### 3. Error & edge cases
Wrong password, generic error message verification, same-path guard, missing input, empty file, files smaller than the minimum header size, and random garbage input. Also verifies that failed operations clean up their output files.

### 4. Format integrity
Encrypted output is always larger than input; minimum output size matches the known header structure.

### 5. Helper unit tests
`makeChunkAD`, `ComputeHeaderHMAC`, `GenerateHeader`, `safeCat`, `zeroBytes`, `GenerateRandomBytes`, and `checkDistinctPaths` are each tested independently.

### 6. Fuzz targets

```bash
# Feed arbitrary bytes to DecryptFile — must never panic
go test -fuzz=FuzzDecrypt -fuzztime=60s

# Verify encrypt→decrypt roundtrip for any input
go test -fuzz=FuzzEncryptDecrypt -fuzztime=60s
```

### Running the tests

```bash
# Full test suite (Argon2 parameters are overridden to fast values in TestMain)
go test -v -timeout 120s ./...

# With race detector
go test -race -timeout 120s ./...

# Vulnerability check on dependencies
govulncheck ./...
```
