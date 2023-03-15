package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

func Base64Decode(encodedString string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func DecryptAES(encryptedData, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key length, must be 16 or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf("invalid encrypted data length")
	}
	iv := encryptedData[:aes.BlockSize]
	encryptedData = encryptedData[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedData, encryptedData)

	return encryptedData, nil
}

// DecodeJWT Decodes a JWT token and returns the payload as a map[string]interface{}.
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
