package encryptdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"log"
	"strings"
)

func DecryptToken(encryptedToken string, key []byte) (string, error) {
	log.Println("\n ***** Decrypt Token  ***** ")

	parts := strings.Split(encryptedToken, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}

	encodedPayload := parts[1]
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return "", errors.New("invalid payload size")
	}
	nonce, encryptedPayload := payload[:nonceSize], payload[nonceSize:]

	decryptedPayload, err := gcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return "", err
	}

	// Reconstruct the JWT token with the decrypted payload
	parts[1] = base64.RawURLEncoding.EncodeToString(decryptedPayload)
	decryptedToken := strings.Join(parts, ".")

	return decryptedToken, nil
}
