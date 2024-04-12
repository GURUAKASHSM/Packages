package encryptdecrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"strings"
)

func EncryptToken(jwtToken string, key []byte) (string, error) {
	log.Println("\n ***** Encrypt Token  ***** ")

	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	encryptedPayload := gcm.Seal(nonce, nonce, payload, nil)

	encodedPayload := base64.RawURLEncoding.EncodeToString(encryptedPayload)

	parts[1] = encodedPayload

	encryptedToken := strings.Join(parts, ".")

	return encryptedToken, nil
}
