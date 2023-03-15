package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

// Prints the usage message for the program.
func usage() {
	// Define colors for syntax highlighting
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()

	// Print usage message with syntax highlighting
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n", bold(os.Args[0]))
	fmt.Fprintln(os.Stderr, "Decode a JWT token and print or save the payload.\n")
	fmt.Fprintln(os.Stderr, "Options:")
	flag.VisitAll(func(flag *flag.Flag) {
		fmt.Fprintf(os.Stderr, "  %s%s%s\t%s\n",
			cyan("--"+flag.Name),          // Flag name in cyan
			" "+bold(flag.Usage),          // Flag usage in bold
			"\t"+bold(red(flag.DefValue)), // Default value in bold red
			strings.ReplaceAll(flag.Usage, "\n", // Description with line breaks
				fmt.Sprintf("\n\t%s", strings.Repeat(" ", 4+len(flag.Name)))))
	})
}

func main() {
	var token, outFile, base64Encoded, aesKeyHex string
	var showHelp bool

	// define flags
	flag.StringVar(&token, "token", "", "JWT token to decode")
	flag.StringVar(&outFile, "out", "", "Output file")
	flag.StringVar(&base64Encoded, "base64", "", "Base64 encoded string to decode")
	flag.StringVar(&aesKeyHex, "aes-key", "", "AES key (hex) for decryption")
	flag.BoolVar(&showHelp, "help", false, "Show help message")

	// set usage message
	flag.Usage = usage

	// parse command-line arguments
	flag.Parse()

	// check for help flag
	if showHelp {
		usage()
		return
	}

	// If JWT token is provided, decode it
	if token != "" {
		// decode token
		payload, err := DecodeJWT(token)
		if err != nil {
			color.Red("Error decoding JWT: %v", err)
			return
		}

		// pretty-print payload
		payloadBytes, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			color.Red("Error encoding payload: %v", err)
			return
		}
		payloadStr := string(payloadBytes)

		// write payload to file or print to stdout
		if outFile != "" {
			f, err := os.Create(outFile)
			if err != nil {
				color.Red("Error creating file: %v", err)
				return
			}
			defer f.Close()

			_, err = f.WriteString(payloadStr)
			if err != nil {
				color.Red("Error writing file: %v", err)
				return
			}
		} else {
			fmt.Println(payloadStr)
		}
	}

	// If base64 encoded string is provided, decode it
	if base64Encoded != "" {
		decodedData, err := Base64Decode(base64Encoded)
		if err != nil {
			fmt.Println("Error decoding base64 string:", err)
			return
		}
		fmt.Println("Decoded data:", string(decodedData))
	}

	// If encrypted data and AES key are provided, decrypt the data
	if base64Encoded != "" && aesKeyHex != "" {
		decodedData, err := Base64Decode(base64Encoded)
		if err != nil {
			fmt.Println("Error decoding base64 string:", err)
			return
		}

		aesKey, err := hex.DecodeString(aesKeyHex)
		if err != nil {
			fmt.Println("Error decoding AES key:", err)
			return
		}

		decryptedData, err := DecryptAES(decodedData, aesKey)
		if err != nil {
			fmt.Println("Error decrypting data:", err)
			return
		}
		fmt.Println("Decrypted data:", string(decryptedData))
	}
}
