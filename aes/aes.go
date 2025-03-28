package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	decryptFlag := flag.Bool("d", false, "Decryption mode")
	generateFlag := flag.Bool("g", false, "Key generation mode")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Encrypt: %s <key-file> < infile > outfile\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Decrypt: %s -d <key-file> < infile > outfile\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Generate key: %s -g <key-file>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *generateFlag {
		if flag.NArg() != 1 {
			fmt.Fprintf(os.Stderr, "Error: No keyfile specified\n")
			flag.Usage()
			os.Exit(1)
		}
		keyFile := flag.Arg(0)
		err := generateKey(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("256-bit key successfully generated and saved to %s\n", keyFile)
		return
	}

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Error: No keyfile specified\n")
		flag.Usage()
		os.Exit(1)
	}

	keyFile := flag.Arg(0)
	key, err := loadKey(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}

	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	if *decryptFlag {
		plaintext, err := decryptMessage(string(input), key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(plaintext)
	} else {
		ciphertext, err := encryptMessage(string(input), key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encryption failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(ciphertext)
	}
}

func loadKey(keyFile string) ([]byte, error) {
	keyData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	hexKey := strings.TrimSpace(strings.ReplaceAll(string(keyData), "\n", ""))
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}

	if len(key) != 32 {
		return nil, errors.New("invalid key length. Expected 32 bytes (256-bit key)")
	}

	return key, nil
}

func generateKey(keyFile string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	hexKey := hex.EncodeToString(key)
	err := ioutil.WriteFile(keyFile, []byte(hexKey), 0600)
	if err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	return nil
}

func encryptMessage(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptMessage(encryptedMessage string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encryptedMessage))
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}