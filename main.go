package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

// Decodes a JWT token and returns the payload as a map[string]interface{}.
func DecodeJWT(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payload, &payloadMap); err != nil {
		return nil, err
	}
	return payloadMap, nil
}

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
	var token string
	var outFile string
	var showHelp bool

	// define flags
	flag.StringVar(&token, "token", "", " JWT token to decode")
	flag.StringVar(&outFile, "out", "", "     output file")
	flag.BoolVar(&showHelp, "help", false, " show help message")

	// set usage message
	flag.Usage = usage

	// parse command-line arguments
	flag.Parse()

	// check for help flag
	if showHelp {
		usage()
		return
	}

	// check for missing token flag
	if token == "" {
		color.Red("Missing token flag")
		flag.Usage()
		return
	}

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

	// write payload to file
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
		// print payload to stdout
		fmt.Println(payloadStr)
	}
}
