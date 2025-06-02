package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

func decryptChunk(enc EncryptedChunk, aesGCM cipher.AEAD) ([]byte, error) {
	plaintext, err := aesGCM.Open(nil, enc.Nonce, enc.Cipher, nil)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Decrypted chunk ID %d\n", enc.ID)
	return plaintext, nil
}

func readChunksFromFile(in *os.File) ([]EncryptedChunk, error) {
	fmt.Println("Reading encrypted chunks from file...")
	var chunks []EncryptedChunk
	for {
		var id int32
		if err := binary.Read(in, binary.BigEndian, &id); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		nonceSizeBuf := make([]byte, 1)
		if _, err := in.Read(nonceSizeBuf); err != nil {
			return nil, err
		}
		nonceSize := int(nonceSizeBuf[0])
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(in, nonce); err != nil {
			return nil, err
		}
		var cipherSize int32
		if err := binary.Read(in, binary.BigEndian, &cipherSize); err != nil {
			return nil, err
		}
		cipher := make([]byte, cipherSize)
		if _, err := io.ReadFull(in, cipher); err != nil {
			return nil, err
		}
		fmt.Printf("Read chunk ID %d from file\n", id)
		chunks = append(chunks, EncryptedChunk{ID: int(id), Nonce: nonce, Cipher: cipher})
	}
	return chunks, nil
}


func RunDecrypt(inputPath, outputPath, keyStr string) {
	fmt.Println("Starting decryption with configuration:")
	fmt.Printf("Input: %s, Output: %s, Key length: %d\n", inputPath, outputPath, len(keyStr))

	key := []byte(keyStr)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesGCM, err := cipher.NewGCM(block)
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

	chunks, err := readChunksFromFile(inFile)
	if err != nil {
		panic(err)
	}
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].ID < chunks[j].ID
	})

	for _, chunk := range chunks {
		plain, err := decryptChunk(chunk, aesGCM)
		if err != nil {
			panic(err)
		}
		if _, err := outFile.Write(plain); err != nil {
			panic(err)
		}
		outFile.Write([]byte("\n"))
	}
	fmt.Println("Decryption complete.")
}