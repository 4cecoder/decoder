package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func EncryptAES(data, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key length, must be 16 or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	paddedData := pkcs7Pad(data, aes.BlockSize)
	encryptedData := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedData, paddedData)
	return append(iv, encryptedData...), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func EncodeJWT(payload map[string]interface{}, secret string) (string, error) {
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := hmac.New(sha256.New, []byte(secret))
	signature.Write([]byte(encodedHeader + "." + encodedPayload))
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature.Sum(nil))
	return encodedHeader + "." + encodedPayload + "." + encodedSignature, nil
}
