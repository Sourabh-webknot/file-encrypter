package crypto

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

type Chunk struct {
	ID   int
	Data []string
}

type EncryptedChunk struct {
	ID     int
	Nonce  []byte
	Cipher []byte
}

func createAESGCM(keyStr string) (cipher.AEAD, error) {
	key := []byte(keyStr)
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d bytes, expected 32 bytes", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesGCM, nil
}

func encryptChunk(chunk Chunk, aesGCM cipher.AEAD) (EncryptedChunk, error) {
	plaintext := []byte(strings.Join(chunk.Data, "\n"))
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedChunk{}, err
	}
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("Encrypted chunk ID %d (%d lines)\n", chunk.ID, len(chunk.Data))
	return EncryptedChunk{ID: chunk.ID, Nonce: nonce, Cipher: ciphertext}, nil
}

func writeChunksToFile(chunks []EncryptedChunk, out *os.File) error {
	fmt.Println("Writing encrypted chunks to output file...")
	for _, chunk := range chunks {
		fmt.Printf("Writing chunk ID %d to file\n", chunk.ID)
		if err := binary.Write(out, binary.BigEndian, int32(chunk.ID)); err != nil {
			return err
		}
		if _, err := out.Write([]byte{byte(len(chunk.Nonce))}); err != nil {
    		return err
		}

		if _, err := out.Write(chunk.Nonce); err != nil {
			return err
		}
		if err := binary.Write(out, binary.BigEndian, int32(len(chunk.Cipher))); err != nil {
			return err
		}
		if _, err := out.Write(chunk.Cipher); err != nil {
			return err
		}
	}
	return nil
}

func RunEncrypt(inputPath, outputPath, keyStr string, chunkSize, workers int) {
	fmt.Println("Starting encryption with configuration:")
	fmt.Printf("Input: %s, Output: %s, Key length: %d, ChunkSize: %d, Workers: %d\n",
		inputPath, outputPath, len(keyStr), chunkSize, workers)

	aesGCM, err := createAESGCM(keyStr)
	if err != nil {
		panic(err)
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	chunkChan := make(chan Chunk, workers)
	resultChan := make(chan EncryptedChunk, workers)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			fmt.Printf("Worker %d started\n", workerID)
			for chunk := range chunkChan {
				fmt.Printf("Worker %d processing chunk ID %d\n", workerID, chunk.ID)
				encChunk, err := encryptChunk(chunk, aesGCM)
				if err != nil {
					fmt.Printf("Worker %d encryption error on chunk %d: %v\n", workerID, chunk.ID, err)
					continue
				}
				resultChan <- encChunk
			}
			fmt.Printf("Worker %d finished\n", workerID)
		}(i)
	}

	go func() {
		scanner := bufio.NewScanner(inFile)
		chunkID := 0
		lines := []string{}
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
			if len(lines) >= chunkSize {
				fmt.Printf("Dispatching chunk ID %d with %d lines\n", chunkID, len(lines))
				chunkChan <- Chunk{ID: chunkID, Data: lines}
				lines = nil
				chunkID++
			}
		}
		if len(lines) > 0 {
			fmt.Printf("Dispatching final chunk ID %d with %d lines\n", chunkID, len(lines))
			chunkChan <- Chunk{ID: chunkID, Data: lines}
		}
		close(chunkChan)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	resultMap := make(map[int]EncryptedChunk)
	for chunk := range resultChan {
		fmt.Printf("Received encrypted chunk ID %d\n", chunk.ID)
		resultMap[chunk.ID] = chunk
	}

	var resultList []EncryptedChunk
	for _, chunk := range resultMap {
		resultList = append(resultList, chunk)
	}
	sort.Slice(resultList, func(i, j int) bool {
		return resultList[i].ID < resultList[j].ID
	})

	if err := writeChunksToFile(resultList, outFile); err != nil {
		panic(err)
	}
	fmt.Println("Encryption complete.")
}