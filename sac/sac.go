package sac

import (
	"bytes"
	"crypto/cipher"
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

var (
	Iterations = uint32(10)
	Memory     = uint32(256 * 1024)
	HmacIter   = uint32(3)
	HmacMemory = uint32(128 * 1024)
)

const (
	Version = 1

	ChunkSize             = 64 * 1024
	ChunkIndexSize        = 4
	DomainSeparatorSize   = 16
	HeaderHmacSize        = 64
	HeaderNonceSize       = 24
	HeaderDomainSeparator = 16
	HeaderSaltSize        = 32
	HmacIVSize            = 32
	HmacSaltSize          = 32
	HmacSize              = 64
	KeySize               = 32
	MaxFileSize           = 256 << 30
	MaxPaddingSize        = 64
	NonceSize             = 24
	SaltSize              = 32
	Threads               = 4

	ChunkADSize = 1 + ChunkIndexSize
)

type FileHeader struct {
	Version                 uint8
	Salt                    [SaltSize]byte
	HMACSalt                [HmacSaltSize]byte
	FileHMACSalt            [HmacSaltSize]byte
	HMACIV                  [HmacIVSize]byte
	HMACDomainSeparator     [DomainSeparatorSize]byte
	FileHMACDomainSeparator [DomainSeparatorSize]byte
	EncDomainSeparator      [DomainSeparatorSize]byte
	PaddingLength           uint32
	DataLength              uint64
}


func EncryptFile(password []byte, inputPath, outputPath string) error {
	defer zeroBytes(password)

	if err := checkDistinctPaths(inputPath, outputPath); err != nil {
		return err
	}


	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inFile.Close()

	inFileInfo, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat input file: %v", err)
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
	defer zeroBytes(headerDomainSeparator)

	headerSalt, err := GenerateRandomBytes(HeaderSaltSize)
	if err != nil {
		return fmt.Errorf("failed to generate header salt: %v", err)
	}
	defer zeroBytes(headerSalt)

	encKey := argon2.IDKey(password, safeCat(header.Salt[:], header.EncDomainSeparator[:]), Iterations, Memory, Threads, KeySize)
	defer zeroBytes(encKey)

	headerHmacKey := argon2.IDKey(password, safeCat(header.HMACSalt[:], header.HMACDomainSeparator[:]), HmacIter, HmacMemory, Threads, KeySize)
	defer zeroBytes(headerHmacKey)

	fileHmacKey := argon2.IDKey(password, safeCat(header.FileHMACSalt[:], header.FileHMACDomainSeparator[:]), HmacIter, HmacMemory, Threads, KeySize)
	defer zeroBytes(fileHmacKey)

	headerKey := argon2.IDKey(password, safeCat(headerDomainSeparator, headerSalt), Iterations, Memory, Threads, KeySize)
	defer zeroBytes(headerKey)


	var aead cipher.AEAD
	aead, err = chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}
	var headerAead cipher.AEAD
	headerAead, err = chacha20poly1305.NewX(headerKey)
	if err != nil {
		return err
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	encryptSucceeded := false
	defer func() {
		outFile.Close()
		if !encryptSucceeded {
			os.Remove(outputPath)
		}
	}()

	if _, err := outFile.Write(headerDomainSeparator); err != nil {
		return err
	}
	if _, err := outFile.Write(headerSalt); err != nil {
		return err
	}

	headerOffset := int64(HeaderDomainSeparator + HeaderSaltSize)
	encryptedHeaderSize := binary.Size(FileHeader{}) + chacha20poly1305.Overhead

	if err := writeHeader(outFile, header, headerAead, headerHmacKey); err != nil {
		return err
	}

	fileMac := hmac.New(sha3.New512, fileHmacKey)
	fileMac.Write(header.HMACIV[:])

	inputBuffer := make([]byte, ChunkSize)
	defer zeroBytes(inputBuffer)

	var chunkIndex uint32

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
			zeroBytes(nonce)
			return err
		}
		paddingSize := paddingSizeBytes[0] % MaxPaddingSize

		var padding []byte
		if paddingSize > 0 {
			padding, err = GenerateRandomBytes(uint(paddingSize))
			if err != nil {
				zeroBytes(nonce)
				return err
			}
		}

		header.DataLength += uint64(n)
		header.PaddingLength += uint32(paddingSize)

		chunkAD := makeChunkAD(paddingSize, chunkIndex)
		ciphertext := aead.Seal(nil, nonce, data, chunkAD)

		writeOK := true
		if _, werr := outFile.Write(nonce); werr != nil {
			writeOK = false
			err = werr
		} else if _, werr := outFile.Write(chunkAD); werr != nil {
			writeOK = false
			err = werr
		} else if _, werr := outFile.Write(ciphertext); werr != nil {
			writeOK = false
			err = werr
		} else if paddingSize > 0 {
			if _, werr := outFile.Write(padding); werr != nil {
				writeOK = false
				err = werr
			}
		}

		fileMac.Write(nonce)
		fileMac.Write(chunkAD)
		fileMac.Write(ciphertext)




		zeroBytes(nonce)
		zeroBytes(ciphertext)

		if !writeOK {
			return err
		}

		chunkIndex++
	}

	if _, err := outFile.Seek(headerOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to header: %v", err)
	}
	if err := writeHeader(outFile, header, headerAead, headerHmacKey); err != nil {
		return fmt.Errorf("failed to write final header: %v", err)
	}

	expectedEnd := headerOffset + int64(HeaderNonceSize+encryptedHeaderSize+HeaderHmacSize)
	pos, err := outFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if pos != expectedEnd {
		return fmt.Errorf("header size mismatch after rewrite: wrote to %d, expected %d", pos, expectedEnd)
	}

	if _, err := outFile.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	fileHmac := fileMac.Sum(nil)
	_, writeErr := outFile.Write(fileHmac)


	zeroBytes(fileHmac)
	if writeErr != nil {
		return writeErr
	}

	encryptSucceeded = true
	return nil
}

func DecryptFile(password []byte, inputPath, outputPath string) error {
	defer zeroBytes(password)

	if err := checkDistinctPaths(inputPath, outputPath); err != nil {
		return err
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inFile.Close()

	inFileInfo, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat input file: %v", err)
	}

	headerSize := int64(
		HeaderDomainSeparator +
			HeaderSaltSize +
			HeaderNonceSize +
			binary.Size(FileHeader{}) +
			chacha20poly1305.Overhead +
			HeaderHmacSize +
			HmacSize)

	if inFileInfo.Size() < headerSize {
		return fmt.Errorf("decryption failed")
	}
	if inFileInfo.Size() > MaxFileSize+headerSize {
		return fmt.Errorf("decryption failed")
	}

	headerDomainSeparator := make([]byte, HeaderDomainSeparator)
	if _, err := io.ReadFull(inFile, headerDomainSeparator); err != nil {
		return fmt.Errorf("decryption failed")
	}

	headerSalt := make([]byte, HeaderSaltSize)
	if _, err := io.ReadFull(inFile, headerSalt); err != nil {
		return fmt.Errorf("decryption failed")
	}

	headerNonce := make([]byte, HeaderNonceSize)
	if _, err := io.ReadFull(inFile, headerNonce); err != nil {
		return fmt.Errorf("decryption failed")
	}

	encryptedHeader := make([]byte, binary.Size(FileHeader{})+chacha20poly1305.Overhead)
	if _, err := io.ReadFull(inFile, encryptedHeader); err != nil {
		return fmt.Errorf("decryption failed")
	}

	storedHeaderHmac := make([]byte, HeaderHmacSize)
	if _, err := io.ReadFull(inFile, storedHeaderHmac); err != nil {
		return fmt.Errorf("decryption failed")
	}

	headerKey := argon2.IDKey(password, safeCat(headerDomainSeparator, headerSalt), Iterations, Memory, Threads, KeySize)
	defer zeroBytes(headerKey)

	zeroBytes(headerDomainSeparator)
	zeroBytes(headerSalt)

	var headerAead cipher.AEAD
	headerAead, err = chacha20poly1305.NewX(headerKey)
	if err != nil {
		return err
	}

	headerBytes, err := headerAead.Open(nil, headerNonce, encryptedHeader, nil)
	if err != nil {
		return fmt.Errorf("decryption failed")
	}
	defer zeroBytes(headerBytes)

	var header FileHeader
	if err := binary.Read(bytes.NewReader(headerBytes), binary.BigEndian, &header); err != nil {
		return fmt.Errorf("decryption failed")
	}

	encKey := argon2.IDKey(password, safeCat(header.Salt[:], header.EncDomainSeparator[:]), Iterations, Memory, Threads, KeySize)
	defer zeroBytes(encKey)

	headerHmacKey := argon2.IDKey(password, safeCat(header.HMACSalt[:], header.HMACDomainSeparator[:]), HmacIter, HmacMemory, Threads, KeySize)
	defer zeroBytes(headerHmacKey)

	fileHmacKey := argon2.IDKey(password, safeCat(header.FileHMACSalt[:], header.FileHMACDomainSeparator[:]), HmacIter, HmacMemory, Threads, KeySize)
	defer zeroBytes(fileHmacKey)

	computedHeaderHmac, err := ComputeHeaderHMAC(header, headerHmacKey)
	if err != nil {
		return fmt.Errorf("decryption failed")
	}

	hmacMatch := subtle.ConstantTimeCompare(storedHeaderHmac, computedHeaderHmac) == 1

	zeroBytes(computedHeaderHmac)

	if !hmacMatch {
		return fmt.Errorf("decryption failed")
	}

	if header.Version != Version {
		return fmt.Errorf("decryption failed")
	}

	if header.DataLength > uint64(MaxFileSize) {
		return fmt.Errorf("decryption failed")
	}

	var aead cipher.AEAD
	aead, err = chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	succeeded := false
	defer func() {
		outFile.Close()
		if !succeeded {
			os.Remove(outputPath)
		}
	}()

	encryptedSize := inFileInfo.Size() - headerSize
	if encryptedSize < 0 {
		return fmt.Errorf("decryption failed")
	}

	fileMac := hmac.New(sha3.New512, fileHmacKey)
	fileMac.Write(header.HMACIV[:])

	nonceBuffer := make([]byte, NonceSize)
	chunkADBuffer := make([]byte, ChunkADSize)
	cipherBuffer := make([]byte, ChunkSize+chacha20poly1305.Overhead)
	var totalPadding uint32
	var remainingData uint64 = header.DataLength
	var expectedChunkIndex uint32

	for encryptedSize > 0 && remainingData > 0 {

		if _, err := io.ReadFull(inFile, nonceBuffer); err != nil {
			return fmt.Errorf("decryption failed")
		}
		encryptedSize -= NonceSize

		if _, err := io.ReadFull(inFile, chunkADBuffer); err != nil {
			return fmt.Errorf("decryption failed")
		}
		encryptedSize -= int64(ChunkADSize)

		paddingSize := chunkADBuffer[0]
		chunkIndex := binary.BigEndian.Uint32(chunkADBuffer[1:])

		if chunkIndex != expectedChunkIndex {
			return fmt.Errorf("decryption failed")
		}
		expectedChunkIndex++

		cipherSize := ChunkSize + chacha20poly1305.Overhead
		if remainingData < ChunkSize {
			cipherSize = int(remainingData) + chacha20poly1305.Overhead
		}
		availableCipher := encryptedSize - int64(paddingSize)
		if availableCipher < 0 {
			return fmt.Errorf("decryption failed")
		}
		if int64(cipherSize) > availableCipher {
			cipherSize = int(availableCipher)
		}

		if _, err := io.ReadFull(inFile, cipherBuffer[:cipherSize]); err != nil {
			return fmt.Errorf("decryption failed")
		}
		ciphertext := cipherBuffer[:cipherSize]
		encryptedSize -= int64(cipherSize)

		fileMac.Write(nonceBuffer)
		fileMac.Write(chunkADBuffer)
		fileMac.Write(ciphertext)

		plaintext, err := aead.Open(nil, nonceBuffer, ciphertext, chunkADBuffer)
		if err != nil {
			return fmt.Errorf("decryption failed")
		}

		_, writeErr := outFile.Write(plaintext)


		zeroBytes(plaintext)
		if writeErr != nil {
			return fmt.Errorf("failed to write decrypted data: %v", writeErr)
		}

		if paddingSize > 0 {
			paddingBuf := make([]byte, paddingSize)
			if _, err := io.ReadFull(inFile, paddingBuf); err != nil {
				return fmt.Errorf("decryption failed")
			}
			encryptedSize -= int64(paddingSize)
		}

		totalPadding += uint32(paddingSize)
		remainingData -= uint64(len(plaintext))
	}

	if totalPadding != header.PaddingLength {
		return fmt.Errorf("decryption failed")
	}

	if encryptedSize != 0 {
		return fmt.Errorf("decryption failed")
	}

	storedHmac := make([]byte, HmacSize)
	if _, err := io.ReadFull(inFile, storedHmac); err != nil {
		return fmt.Errorf("decryption failed")
	}
	computedHmac := fileMac.Sum(nil)
	fileHmacMatch := subtle.ConstantTimeCompare(storedHmac, computedHmac) == 1

	zeroBytes(computedHmac)

	if !fileHmacMatch {
		return fmt.Errorf("decryption failed")
	}

	succeeded = true
	return nil
}

func writeHeader(dst *os.File, h FileHeader, hAead cipher.AEAD, hmacKey []byte) error {
	nonce, err := GenerateRandomBytes(HeaderNonceSize)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, &h); err != nil {
		zeroBytes(nonce)
		return fmt.Errorf("failed to serialise header: %v", err)
	}

	enc := hAead.Seal(nil, nonce, buf.Bytes(), nil)

	_, nonceErr := dst.Write(nonce)
	zeroBytes(nonce)
	if nonceErr != nil {
		zeroBytes(enc)
		return nonceErr
	}

	_, encErr := dst.Write(enc)
	zeroBytes(enc)
	if encErr != nil {
		return encErr
	}

	mac, err := ComputeHeaderHMAC(h, hmacKey)
	if err != nil {
		return fmt.Errorf("failed to compute header HMAC: %v", err)
	}
	_, macErr := dst.Write(mac)
	zeroBytes(mac)
	return macErr
}

func makeChunkAD(paddingSize byte, chunkIndex uint32) []byte {
	ad := make([]byte, ChunkADSize)
	ad[0] = paddingSize
	binary.BigEndian.PutUint32(ad[1:], chunkIndex)
	return ad
}

func ComputeHeaderHMAC(header FileHeader, hmacKey []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to serialise header: %v", err)
	}
	mac := hmac.New(sha3.New512, hmacKey)
	mac.Write(buf.Bytes())
	return mac.Sum(nil), nil
}

func GenerateHeader() (FileHeader, error) {
	var header FileHeader
	header.Version = Version

	type field struct {
		size uint
		dst  []byte
		name string
	}

	fields := []field{
		{SaltSize, header.Salt[:], "salt"},
		{HmacSaltSize, header.HMACSalt[:], "HMAC salt"},
		{HmacSaltSize, header.FileHMACSalt[:], "file HMAC salt"},
		{DomainSeparatorSize, header.EncDomainSeparator[:], "encryption domain separator"},
		{DomainSeparatorSize, header.HMACDomainSeparator[:], "HMAC domain separator"},
		{DomainSeparatorSize, header.FileHMACDomainSeparator[:], "file HMAC domain separator"},
		{HmacIVSize, header.HMACIV[:], "HMAC IV"},
	}

	for _, f := range fields {
		b, err := GenerateRandomBytes(f.size)
		if err != nil {
			return header, fmt.Errorf("failed to generate %s: %v", f.name, err)
		}
		copy(f.dst, b)
	}

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

func safeCat(a, b []byte) []byte {
	out := make([]byte, len(a)+len(b))
	copy(out, a)
	copy(out[len(a):], b)
	return out
}

func zeroBytes(b []byte) {
	subtle.ConstantTimeCopy(1, b, make([]byte, len(b)))
}

func checkDistinctPaths(src, dst string) error {
	if src == dst {
		return fmt.Errorf("input and output paths must be different")
	}
	srcInfo, err := os.Stat(src)
	if err != nil {
		return nil
	}
	dstInfo, err := os.Stat(dst)
	if err != nil {
		return nil
	}
	if os.SameFile(srcInfo, dstInfo) {
		return fmt.Errorf("input and output paths must be different")
	}
	return nil
}
