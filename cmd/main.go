// Concurrent chunked file encryption and decryption in Go
// AES-GCM based encryption with worker pool and verbose logging

package main

import (
	"assignment1/internal/crypto"
	_ "bufio"
	"flag"
	"fmt"
	"os"
	_ "sync"
)

// type Chunk struct {
// 	ID   int
// 	Data []string
// }

// // type EncryptedChunk struct {
// // 	ID     int
// // 	Nonce  []byte
// // 	Cipher []byte
// // }

const DefaultLinesPerChunk = 1000
const DefaultNumWorkers = 4


func main() {


	if len(os.Args) < 2 {
		fmt.Println("Expected 'encrypt' or 'decrypt' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encrypt":
		encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
		inputPath := encryptCmd.String("file", "", "Input file path")
		outputPath := encryptCmd.String("out", "", "Output file path")
		keyStr := encryptCmd.String("key", "", "32-byte AES key")
		chunkSize := encryptCmd.Int("chunkSize", DefaultLinesPerChunk, "Lines per chunk")
		workers := encryptCmd.Int("workers", DefaultNumWorkers, "Number of workers")

		encryptCmd.Parse(os.Args[2:])

		// Validate required flags
		if *inputPath == "" || *outputPath == "" || *keyStr == "" {
			fmt.Println("encrypt requires --file, --out and --key flags")
			encryptCmd.PrintDefaults()
			os.Exit(1)
		}

		crypto.RunEncrypt(*inputPath, *outputPath, *keyStr, *chunkSize, *workers)

	case "decrypt":
		decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
		inputPath := decryptCmd.String("file", "", "Input file path")
		outputPath := decryptCmd.String("out", "", "Output file path")
		keyStr := decryptCmd.String("key", "", "32-byte AES key")

		decryptCmd.Parse(os.Args[2:])

		if *inputPath == "" || *outputPath == "" || *keyStr == "" {
			fmt.Println("decrypt requires --file, --out and --key flags")
			decryptCmd.PrintDefaults()
			os.Exit(1)
		}

		crypto.RunDecrypt(*inputPath, *outputPath, *keyStr)

	default:
		fmt.Println("Expected 'encrypt' or 'decrypt' subcommands")
		os.Exit(1)
	}
}
