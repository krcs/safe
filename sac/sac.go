package sac

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

const (
	Version = 1 // File format version

	ChunkSize             = 64 * 1024  // 64KB chunks
	DomainSeparatorSize   = 16         // Size of random domain separators
	HeaderHmacSize        = 64         // Size of header HMAC
	HeaderNonceSize       = 24         // Nonce size for header encryption
	HeaderDomainSeparator = 16         // Size of random domain separator for header key
	HeaderSaltSize        = 32         // Salt size for header key (moved outside FileHeader)
	HmacIVSize            = 32         // Increased HMAC IV size
	HmacIter              = 3          // Increased iterations for HMAC key
	HmacMemory            = 128 * 1024 // Increased to 128MB for HMAC key
	HmacSaltSize          = 32         // Salt size for HMAC key
	HmacSize              = 64         // SHA3-512 HMAC size
	Iterations            = 10         // Increased iterations for Argon2
	KeySize               = 32         // 256-bit key (quantum-safe for symmetric crypto)
	MaxFileSize           = 256 << 30  // maximum file size
	MaxPaddingSize        = 64         // Maximum random padding size per chunk
	Memory                = 256 * 1024 // Increased to 256MB for quantum resistance
	NonceSize             = 24         // ChaCha20-Poly1305 nonce size for data
	SaltSize              = 32         // Salt size for encryption key
	Threads               = 4          // Number of threads for Argon2
)

type FileHeader struct {
	Version             uint8                     // File format version
	Salt                [SaltSize]byte            // Salt for encryption key
	HMACSalt            [HmacSaltSize]byte        // Salt for HMAC key
	HMACIV              [HmacIVSize]byte          // IV for file HMAC
	HMACDomainSeparator [DomainSeparatorSize]byte // Random domain separator for HMAC key
	EncDomainSeparator  [DomainSeparatorSize]byte // Random domain separator for encryption key
	PaddingLength       uint32                    // Total padding length
	DataLength          uint64                    // Total original data length
}

func EncryptFile(password []byte, inputPath, outputPath string) error {
	inFileInfo, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("failed to get input file info: %v", err)
	}
	if inFileInfo.Size() > MaxFileSize {
		return fmt.Errorf("file size %d exceeds maximum allowed size of %d bytes", inFileInfo.Size(), MaxFileSize)
	}

	header, err := GenerateHeader()
	if err != nil {
		return err
	}

	headerDomainSeparator, err := GenerateRandomBytes(HeaderDomainSeparator)
	if err != nil {
		return fmt.Errorf("failed to generate header domain separator: %v", err)
	}
	headerSalt, err := GenerateRandomBytes(HeaderSaltSize)
	if err != nil {
		return fmt.Errorf("failed to generate header salt: %v", err)
	}

	encKey := argon2.IDKey(password, append(header.Salt[:], header.EncDomainSeparator[:]...), Iterations, Memory, Threads, KeySize)
	hmacKey := argon2.IDKey(password, append(header.HMACSalt[:], header.HMACDomainSeparator[:]...), HmacIter, HmacMemory, Threads, KeySize)
	headerKey := argon2.IDKey(password, append(headerSalt, headerDomainSeparator...), Iterations, Memory, Threads, KeySize)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}
	headerAead, err := chacha20poly1305.NewX(headerKey)
	if err != nil {
		return err
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if _, err := outFile.Write(headerDomainSeparator); err != nil {
		return err
	}
	if _, err := outFile.Write(headerSalt); err != nil {
		return err
	}

	headerBytes := new(bytes.Buffer)
	if err := binary.Write(headerBytes, binary.BigEndian, &header); err != nil {
		return err
	}

	headerNonce, err := GenerateRandomBytes(HeaderNonceSize)
	if err != nil {
		return err
	}
	encryptedHeader := headerAead.Seal(nil, headerNonce, headerBytes.Bytes(), nil)

	if _, err := outFile.Write(headerNonce); err != nil {
		return err
	}
	if _, err := outFile.Write(encryptedHeader); err != nil {
		return err
	}

	headerHmac := ComputeHeaderHMAC(header, hmacKey)
	if _, err := outFile.Write(headerHmac); err != nil {
		return err
	}

	fileMac := hmac.New(sha3.New512, hmacKey)
	fileMac.Write(header.HMACIV[:])

	inputBuffer := make([]byte, ChunkSize)
	for {
		n, err := io.ReadFull(inFile, inputBuffer)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		data := inputBuffer[:n]

		nonce, err := GenerateRandomBytes(NonceSize)
		if err != nil {
			return err
		}

		paddingSizeBytes, err := GenerateRandomBytes(1)
		if err != nil {
			return err
		}
		paddingSize := paddingSizeBytes[0] % MaxPaddingSize
		padding, err := GenerateRandomBytes(uint(paddingSize))
		if err != nil {
			return err
		}

		header.DataLength += uint64(n)
		header.PaddingLength += uint32(paddingSize)

		chunkHeaderBytes := []byte{paddingSize}

		ciphertext := aead.Seal(nil, nonce, data, chunkHeaderBytes)

		if _, err := outFile.Write(nonce); err != nil {
			return err
		}
		if err := binary.Write(outFile, binary.BigEndian, chunkHeaderBytes); err != nil {
			return err
		}
		if _, err := outFile.Write(ciphertext); err != nil {
			return err
		}
		if _, err := outFile.Write(padding); err != nil {
			return err
		}

		fileMac.Write(nonce)
		fileMac.Write(chunkHeaderBytes)
		fileMac.Write(data)
	}

	headerBytes.Reset()
	if err := binary.Write(headerBytes, binary.BigEndian, &header); err != nil {
		return err
	}
	encryptedHeader = headerAead.Seal(nil, headerNonce, headerBytes.Bytes(), nil)

	if _, err := outFile.Seek(int64(HeaderDomainSeparator+HeaderSaltSize), io.SeekStart); err != nil {
		return err
	}
	if _, err := outFile.Write(headerNonce); err != nil {
		return err
	}
	if _, err := outFile.Write(encryptedHeader); err != nil {
		return err
	}
	headerHmac = ComputeHeaderHMAC(header, hmacKey)
	if _, err := outFile.Write(headerHmac); err != nil {
		return err
	}

	if _, err := outFile.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	fileHmac := fileMac.Sum(nil)
	if _, err := outFile.Write(fileHmac); err != nil {
		return err
	}

	return nil
}

func DecryptFile(password []byte, inputPath, outputPath string) error {
	inFileInfo, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("failed to get input file info: %v", err)
	}

	headerSize := int64(
		HeaderDomainSeparator +
			HeaderSaltSize + HeaderNonceSize +
			binary.Size(FileHeader{}) +
			chacha20poly1305.Overhead +
			HeaderHmacSize +
			HmacSize)

	if inFileInfo.Size() > MaxFileSize+headerSize {
		return fmt.Errorf("encrypted file size %d exceeds maximum allowed size", inFileInfo.Size())
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	headerDomainSeparator := make([]byte, HeaderDomainSeparator)
	if _, err := io.ReadFull(inFile, headerDomainSeparator); err != nil {
		return fmt.Errorf("failed to read header domain separator: %v", err)
	}

	headerSalt := make([]byte, HeaderSaltSize)
	if _, err := io.ReadFull(inFile, headerSalt); err != nil {
		return fmt.Errorf("failed to read header salt: %v", err)
	}

	headerNonce := make([]byte, HeaderNonceSize)
	if _, err := io.ReadFull(inFile, headerNonce); err != nil {
		return fmt.Errorf("failed to read header nonce: %v", err)
	}

	encryptedHeader := make([]byte, binary.Size(FileHeader{})+chacha20poly1305.Overhead)
	if _, err := io.ReadFull(inFile, encryptedHeader); err != nil {
		return fmt.Errorf("failed to read encrypted header: %v", err)
	}

	storedHeaderHmac := make([]byte, HeaderHmacSize)
	if _, err := io.ReadFull(inFile, storedHeaderHmac); err != nil {
		return fmt.Errorf("failed to read header HMAC: %v", err)
	}

	headerKey := argon2.IDKey(password, append(headerSalt, headerDomainSeparator...), Iterations, Memory, Threads, KeySize)
	headerAead, err := chacha20poly1305.NewX(headerKey)
	if err != nil {
		return err
	}

	headerBytes, err := headerAead.Open(nil, headerNonce, encryptedHeader, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt header (possible wrong password): %v", err)
	}

	var header FileHeader
	if err := binary.Read(bytes.NewReader(headerBytes), binary.BigEndian, &header); err != nil {
		return err
	}

	encKey := argon2.IDKey(password, append(header.Salt[:], header.EncDomainSeparator[:]...), Iterations, Memory, Threads, KeySize)
	hmacKey := argon2.IDKey(password, append(header.HMACSalt[:], header.HMACDomainSeparator[:]...), HmacIter, HmacMemory, Threads, KeySize)

	computedHeaderHmac := ComputeHeaderHMAC(header, hmacKey)
	if subtle.ConstantTimeCompare(storedHeaderHmac, computedHeaderHmac) != 1 {
		return fmt.Errorf("header integrity check failed")
	}

	if header.Version != Version {
		return fmt.Errorf("unsupported file version: %d", header.Version)
	}

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	headerSize = int64(HeaderDomainSeparator + HeaderSaltSize + HeaderNonceSize + len(encryptedHeader) + HeaderHmacSize + HmacSize)

	encryptedSize := inFileInfo.Size() - headerSize
	if encryptedSize < 0 {
		return fmt.Errorf("invalid file size: too small to contain encrypted data")
	}

	fileMac := hmac.New(sha3.New512, hmacKey)
	fileMac.Write(header.HMACIV[:])

	nonceBuffer := make([]byte, NonceSize)
	cipherBuffer := make([]byte, ChunkSize+chacha20poly1305.Overhead)
	var totalPadding uint32
	var remainingData uint64 = header.DataLength

	for encryptedSize > 0 && remainingData > 0 {
		if _, err := io.ReadFull(inFile, nonceBuffer); err != nil {
			return fmt.Errorf("failed to read nonce: %v", err)
		}
		encryptedSize -= NonceSize

		var chunkHeader uint8
		if err := binary.Read(inFile, binary.BigEndian, &chunkHeader); err != nil {
			return fmt.Errorf("failed to read chunk header: %v", err)
		}
		encryptedSize -= int64(binary.Size(chunkHeader))
		chunkHeaderBytes := []byte{chunkHeader}

		cipherSize := ChunkSize + chacha20poly1305.Overhead
		if remainingData < ChunkSize {
			cipherSize = int(remainingData) + chacha20poly1305.Overhead
		}
		if int64(cipherSize) > encryptedSize-int64(chunkHeader) {
			cipherSize = int(encryptedSize) - int(chunkHeader)
		}
		_, err := io.ReadFull(inFile, cipherBuffer[:cipherSize])
		if err != nil {
			return fmt.Errorf("failed to read ciphertext: %v", err)
		}
		ciphertext := cipherBuffer[:cipherSize]
		encryptedSize -= int64(cipherSize)

		plaintext, err := aead.Open(nil, nonceBuffer, ciphertext, chunkHeaderBytes)
		if err != nil {
			return fmt.Errorf("decryption failed: %v", err)
		}

		if _, err := outFile.Write(plaintext); err != nil {
			return err
		}

		padding := make([]byte, chunkHeader)
		if _, err := io.ReadFull(inFile, padding); err != nil {
			return fmt.Errorf("failed to read padding: %v", err)
		}
		encryptedSize -= int64(chunkHeader)

		totalPadding += uint32(chunkHeader)
		remainingData -= uint64(len(plaintext))

		fileMac.Write(nonceBuffer)
		fileMac.Write(chunkHeaderBytes)
		fileMac.Write(plaintext)
	}

	if totalPadding != header.PaddingLength {
		os.Remove(outputPath)
		return fmt.Errorf("padding verification failed: expected %d, got %d", header.PaddingLength, totalPadding)
	}

	storedHmac := make([]byte, HmacSize)
	_, err = io.ReadFull(inFile, storedHmac)
	if err != nil {
		return fmt.Errorf("failed to read HMAC: %v", err)
	}
	computedHmac := fileMac.Sum(nil)

	if subtle.ConstantTimeCompare(storedHmac, computedHmac) != 1 {
		os.Remove(outputPath)
		return fmt.Errorf("file integrity check failed")
	}

	return nil
}

func ComputeHeaderHMAC(header FileHeader, hmacKey []byte) []byte {
	headerBytes := make([]byte, binary.Size(header))
	headerBytes[0] = header.Version
	copy(headerBytes[1:], header.Salt[:])
	copy(headerBytes[1+SaltSize:], header.HMACSalt[:])
	copy(headerBytes[1+SaltSize+HmacSaltSize:], header.EncDomainSeparator[:])
	copy(headerBytes[1+SaltSize+HmacSaltSize+DomainSeparatorSize:], header.HMACDomainSeparator[:])
	copy(headerBytes[1+SaltSize+HmacSaltSize+2*DomainSeparatorSize:], header.HMACIV[:])
	binary.BigEndian.PutUint64(headerBytes[1+SaltSize+HmacSaltSize+2*DomainSeparatorSize+HmacIVSize:], header.DataLength)
	binary.BigEndian.PutUint32(headerBytes[1+SaltSize+HmacSaltSize+2*DomainSeparatorSize+HmacIVSize+8:], header.PaddingLength)

	headerMac := hmac.New(sha3.New512, hmacKey)
	headerMac.Write(headerBytes)
	return headerMac.Sum(nil)
}

func GenerateHeader() (FileHeader, error) {
	var header FileHeader

	header.Version = Version

	salt, err := GenerateRandomBytes(SaltSize)
	if err != nil {
		return header, fmt.Errorf("failed to generate salt: %v", err)
	}
	copy(header.Salt[:], salt)

	hmacSalt, err := GenerateRandomBytes(HmacSaltSize)
	if err != nil {
		return header, fmt.Errorf("failed to generate HMAC salt: %v", err)
	}
	copy(header.HMACSalt[:], hmacSalt)

	encDomain, err := GenerateRandomBytes(DomainSeparatorSize)
	if err != nil {
		return header, fmt.Errorf("failed to generate encryption domain separator: %v", err)
	}
	copy(header.EncDomainSeparator[:], encDomain)

	hmacDomain, err := GenerateRandomBytes(DomainSeparatorSize)
	if err != nil {
		return header, fmt.Errorf("failed to generate HMAC domain separator: %v", err)
	}
	copy(header.HMACDomainSeparator[:], hmacDomain)

	hmacIV, err := GenerateRandomBytes(HmacIVSize)
	if err != nil {
		return header, fmt.Errorf("failed to generate HMAC IV: %v", err)
	}
	copy(header.HMACIV[:], hmacIV)

	header.DataLength = 0
	header.PaddingLength = 0

	return header, nil
}

func GenerateRandomBytes(n uint) ([]byte, error) {
	result := make([]byte, n)
	if _, err := rand.Read(result); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	return result, nil
}
