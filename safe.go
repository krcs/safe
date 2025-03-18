package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"
	"safe/sac"
)

const (
	AppName    = "Stand-Alone File Encryptor"
	AppVersion = "1.0"
)

func PrintVersion() {
	fmt.Printf("%s v%s (K!2025), File Version: v%d\n\n", AppName, AppVersion, sac.Version)
}

func PrintUsage(progName string) {
	PrintVersion()
	fmt.Printf(" Usage: %s <command> [flags]\n\n", progName)
	fmt.Println(" Commands:")
	fmt.Println("   encrypt -i <input file> -o <output file> [-k <key>]")
	fmt.Println("   decrypt -i <input file> -o <output file> [-k <key>]\n")
	fmt.Println(" Global Flags:")
	fmt.Println("   -h, --help     Show this help information")
	fmt.Println("   -v, --version  Show version information\n")
	fmt.Println(" Command Flags:")
	fmt.Println("   -i, --input    Input file")
	fmt.Println("   -o, --output   Output file")
	fmt.Printf("   -k, --key      Key (at least %d bytes)\n", sac.KeySize)
	fmt.Println()
}

func GetKey(value string) ([]byte, error) {
	if len(value) != 0 {
		return []byte(value), nil
	}
	fmt.Println("Enter key: ")

	var key []byte
	key, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func main() {
	progName := filepath.Base(os.Args[0])

	if len(os.Args) < 2 {
		PrintUsage(progName)
		os.Exit(1)
	}

	help := flag.Bool("h", false, "Show help information")
	flag.BoolVar(help, "help", false, "Show help information")

	version := flag.Bool("v", false, "Show version information")
	flag.BoolVar(version, "version", false, "Show version information")

	// ENCRYPT
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)

	encryptInput := encryptCmd.String("i", "", "Input file to encrypt")
	encryptCmd.StringVar(encryptInput, "input", "", "Input file to encrypt (alternative to -i)")

	encryptOutput := encryptCmd.String("o", "", "Output encrypted file")
	encryptCmd.StringVar(encryptOutput, "output", "", "Output encrypted file (alternative to -o)")

	encryptKey := encryptCmd.String("k", "", "Encryption key")
	encryptCmd.StringVar(encryptKey, "key", "", "Encryption key (alternative to -k)")

	// DECRYPT
	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decryptInput := decryptCmd.String("i", "", "Input encrypted file")
	decryptCmd.StringVar(decryptInput, "input", "", "Input encrypted file (alternative to -i)")

	decryptOutput := decryptCmd.String("o", "", "Output decrypted file")
	decryptCmd.StringVar(decryptOutput, "output", "", "Output decrypted file (alternative to -o)")

	decryptKey := decryptCmd.String("k", "", "Decryption key")
	decryptCmd.StringVar(decryptKey, "key", "", "Decryption key (alternative to -k)")

	flag.Parse()

	if *help {
		PrintUsage(progName)
		os.Exit(0)
	}

	if *version {
		PrintVersion()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
		if *encryptInput == "" || *encryptOutput == "" {
			fmt.Println("encrypt: flags (-i, -o) are required")
			encryptCmd.Usage()
			os.Exit(1)
		}

		key, err := GetKey(*encryptKey)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = sac.EncryptFile(key, *encryptInput, *encryptOutput)
		if err != nil {
			fmt.Println("Encryption error:", err)
			os.Exit(1)
		}
		fmt.Println("Encryption completed successfully")

	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
		if *decryptInput == "" || *decryptOutput == "" {
			fmt.Println("decrypt: flags (-i, -o) are required")
			decryptCmd.Usage()
			os.Exit(1)
		}

		key, err := GetKey(*decryptKey)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = sac.DecryptFile(key, *decryptInput, *decryptOutput)
		if err != nil {
			fmt.Println("Decryption error:", err)
			os.Exit(1)
		}
		fmt.Println("Decryption completed successfully")

	default:
		PrintUsage(progName)
		os.Exit(1)
	}
}
