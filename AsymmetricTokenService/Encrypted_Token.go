package asymmetrictokenservice

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// CreateAsymmetricEncryptedToken creates an encrypted token using asymmetric encryption
func CreateAsymmetricEncryptedToken(email, id string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, validTime time.Duration) (string, error) {
	log.Println("\n ****** Create Asymmetric Encrypted Token ****** ")

	// Create the JWT token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"email": email,
		"id":    id,
		"exp":   time.Now().Add(validTime).Unix(),
	})

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	// Encrypt the token using the public key
	encryptedToken, err := EncryptToken(tokenString, publicKey)
	if err != nil {
		return "", err
	}

	return encryptedToken, nil
}

func EncryptToken(jwtToken string, publicKey *rsa.PublicKey) (string, error) {
	log.Println("\n ***** Encrypt Token  ***** ")

	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	symmetricKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(symmetricKey); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(symmetricKey)
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

	encryptedSymmetricKey, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, symmetricKey)
	if err != nil {
		return "", err
	}
	encodedSymmetricKey := base64.RawURLEncoding.EncodeToString(encryptedSymmetricKey)

	parts[1] = encodedPayload
	parts[2] = encodedSymmetricKey

	encryptedToken := strings.Join(parts, ".")

	return encryptedToken, nil
}

func DecryptToken(encryptedToken string, privateKey *rsa.PrivateKey) (string, error) {
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

	encodedSymmetricKey := parts[2]
	symmetricKey, err := base64.RawURLEncoding.DecodeString(encodedSymmetricKey)
	if err != nil {
		return "", err
	}

	decryptedSymmetricKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, symmetricKey)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(decryptedSymmetricKey)
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

	parts[1] = base64.RawURLEncoding.EncodeToString(decryptedPayload)
	decryptedToken := strings.Join(parts, ".")

	return decryptedToken, nil
}
