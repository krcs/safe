package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/term"
	"safe/sac"
)

var AppVersion = "1.0"
var AppName    = "Stand-Alone File Encryptor"

func PrintVersion() {
	fmt.Printf("%s v%s (K!2025)\nFile Version: v%d\n\n", AppName, AppVersion, sac.Version)
}

func PrintUsage() {
	progName := filepath.Base(os.Args[0])
	PrintVersion()
	fmt.Printf("  Usage: %s <command> [flags]\n\n", progName)
	fmt.Println(" Commands:")
	fmt.Println("   encrypt -i <input file> -o <output file> [-p <password>]")
	fmt.Println("   decrypt -i <input file> -o <output file> [-p <password>]")
	fmt.Println()
	fmt.Println(" Global Flags:")
	fmt.Println("   -h, --help       Show this help information")
	fmt.Println("   -v, --version    Show version information")
	fmt.Println()
	fmt.Println(" Command Flags:")
	fmt.Println("   -i, --input      Input file")
	fmt.Println("   -o, --output     Output file")
	fmt.Println("   -p, --password")
	fmt.Println("   -vp, --verify    Confirm password if it is entered through the standard input.")
	fmt.Println("                    Ignored when the -p flag is specified.")
	fmt.Println()
	flag.PrintDefaults()
}

func GetPassword(value string, verify bool) ([]byte, error) {
	if len(value) != 0 {
		return []byte(value), nil
	}
	fmt.Println("Enter password: ")

	var password []byte
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}

	if !verify {
		return password, nil
	}
	var vpassword []byte
	fmt.Println("Verfiy password: ")
	vpassword, err = term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}

	if !slices.Equal(password, vpassword) {
		return nil, fmt.Errorf("passwords doesn't match")
	}

	return password, nil
}

func main() {
	flag.Usage = PrintUsage;

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	help := flag.Bool("h", false, "Show help information")
	flag.BoolVar(help, "help", false, "Show help information")

	version := flag.Bool("v", false, "Show version information")
	flag.BoolVar(version, "version", false, "Show version information")

	command := flag.NewFlagSet("command", flag.ExitOnError)

	input := command.String("i", "", "Input file")
	command.StringVar(input, "input", "", "Input file (alternative to -i)")

	output := command.String("o", "", "Output file")
	command.StringVar(output, "output", "", "Output file (alternative to -o)")

	password := command.String("p", "", "Password")
	command.StringVar(password, "password", "", "Password (alternative to -p)")

	verify := command.Bool("vp", false, "Verfiy password")
	command.BoolVar(verify, "verify", false, "Verfiy password")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *version {
		PrintVersion()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "encrypt":
		command.Parse(os.Args[2:])
		if *input == "" || *output == "" {
			fmt.Println("encrypt: flags (-i, -o) are required")
			os.Exit(1)
		}

		passwordBytes, err := GetPassword(*password, *verify)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = sac.EncryptFile(passwordBytes, *input, *output)
		if err != nil {
			fmt.Println("Encryption error:", err)
			os.Exit(1)
		}
		fmt.Println("Encryption completed successfully")

	case "decrypt":
		command.Parse(os.Args[2:])
		if *input == "" || *output == "" {
			fmt.Println("decrypt: flags (-i, -o) are required")
			os.Exit(1)
		}

		passwordBytes, err := GetPassword(*password, *verify)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = sac.DecryptFile(passwordBytes, *input, *output)
		if err != nil {
			fmt.Println("Decryption error:", err)
			os.Exit(1)
		}
		fmt.Println("Decryption completed successfully")

	default:
		flag.Usage()
		os.Exit(1)
	}
}
