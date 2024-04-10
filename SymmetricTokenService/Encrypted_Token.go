package symmetrictokenservice

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func CreateEncryptedToken(email, id, SecretKey string, validtime int64, key []byte) (string, error) {
	log.Println("\n ****** Create Encrypted Token ****** ")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"id":    id,
		"exp":   time.Now().Add(time.Hour * time.Duration(validtime)).Unix(),
	})

	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return "", err
	}
	encrypetedtoken, err := EncryptToken(tokenString, key)
	if err != nil {
		return "", err
	}
	return encrypetedtoken, nil
}

func ExtractIdFromEncryptedToken(jwtToken string, secretKey string, key []byte) (string, error) {
	log.Println("\n ****** Extract ID From Encrypted Token ****** ")

	decryptedToken, err := DecryptToken(jwtToken, key)
	if err != nil {
		return "", err
	}

	token, err := jwt.Parse(decryptedToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		log.Println(err)
		return "", err
	}

	if token.Valid {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			id, ok := claims["id"].(string)
			if ok {
				return id, nil
			}
		}
	}

	return "", fmt.Errorf("invalid or expired JWT token")
}

func ExtractDetailsFromEncryptedToken(jwtToken string, secretKey string, key []byte) (map[string]interface{}, error) {
	log.Println("\n ****** Extract Details Form Encrypted Token ****** ")

	decryptedToken, err := DecryptToken(jwtToken, key)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(decryptedToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		log.Println(err)
		return nil, err
	}

	if token.Valid {

		if claims, ok := token.Claims.(jwt.MapClaims); ok {

			return claims, nil
		}
	}

	return nil, fmt.Errorf("invalid or expired JWT token")
}

func ValidateEncryptedtoken(jwtToken, SecretKey string, key []byte) (bool, error) {
	log.Println("\n ****** Validate Encrypted Token ****** ")

	decryptedToken, err := DecryptToken(jwtToken, key)
	if err != nil {
		return false, err
	}

	token, err := jwt.Parse(decryptedToken, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(SecretKey), nil
	})

	if err != nil {
		log.Println(err)
		return false, nil
	}

	if token.Valid {
		return true, nil
	}

	return false, nil
}

func (tm *TokenManager) BlockEncryptedToken(token string, key []byte) error {
	log.Println("\n ****** Block Encrypted Token ****** ")

	decryptedToken, err := DecryptToken(token, key)
	if err != nil {
		return err
	}

	expirationTime, err := ExtractExpirationTimeFromToken(decryptedToken) // Fix here
	if err != nil {
		return err
	}

	tm.revokedTokensMutex.Lock()
	defer tm.revokedTokensMutex.Unlock()

	tm.revokedTokens[decryptedToken] = expirationTime // Fix here

	return nil
}

func (tm *TokenManager) UnblockEncryptedToken(encryptedToken,SecretKey string, key []byte) error {
	log.Println("\n ****** UnBlock Encrypted Token ****** ")

	// Decrypt the token to extract its contents
	decryptedToken, err := DecryptToken(encryptedToken, key)
	if err != nil {
		return err
	}

	expirationTime, err := ExtractExpirationTimeFromToken(decryptedToken)
	if err != nil {
		return err
	}
	tm.revokedTokensMutex.Lock()
	defer tm.revokedTokensMutex.Unlock()
	for token, exp := range tm.revokedTokens {
		if exp.Equal(expirationTime) {
			delete(tm.revokedTokens, token)
			return nil
		}
	}
	return fmt.Errorf("no token with expiration time '%s' is blocked", expirationTime)
}


func (tm *TokenManager) IsEncryptedTokenBlocked(token string, key []byte) (bool, error) {
	log.Println("\n ****** Is Encrypted Token Blocked****** ")
	decryptedToken, err := DecryptToken(token, key)
	if err != nil {
		return false, err
	}
	tm.revokedTokensMutex.RLock()
	defer tm.revokedTokensMutex.RUnlock()

	expirationTime, found := tm.revokedTokens[decryptedToken]
	if !found {
		return false, nil
	}
    
	return time.Now().Before(expirationTime), nil
}

func GenerateAccessAndRefreshEncryptedTokens(email, id, SecretKey string, key []byte) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Encrypted Token *****")

	accessToken, err := CreateToken(email, id, SecretKey, 1)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	refreshToken, err := CreateToken(email, id, SecretKey, 1*24*7)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	accessToken, err = EncryptToken(accessToken, key)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = EncryptToken(refreshToken, key)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func RefreshAccessEncryptedToken(refreshToken, SecretKey string, key []byte) (string, error) {
	log.Println("\n ***** Refresh Access Encrypted Token ***** ")

	decryptedToken, err := DecryptToken(refreshToken, key)
	if err != nil {
		return "", err
	}

	claims, err := ExtractDetailsFromToken(decryptedToken, SecretKey)
	if err != nil {
		return "", err
	}

	exp := int64(claims["exp"].(float64))
	if time.Now().Unix() > exp {
		return "", fmt.Errorf("refresh token has expired")
	}

	accessToken, err := CreateToken(claims["email"].(string), claims["id"].(string), SecretKey, 1)
	if err != nil {
		return "", err
	}

	accessToken, err = EncryptToken(accessToken, key)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func ExtractExpirationTimeFromEncryptedToken(jwtToken string, key []byte) (time.Time, error) {
	log.Println("\n ***** Extract Expiration Time From Encrypted Token ***** ")

	decryptedToken, err := DecryptToken(jwtToken, key)
	if err != nil {
		return time.Time{}, err
	}

	token, _, err := new(jwt.Parser).ParseUnverified(decryptedToken, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return time.Time{}, errors.New("invalid token claims")
	}

	expClaim, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, errors.New("expiration time (exp) claim not found or invalid")
	}

	expirationTime := time.Unix(int64(expClaim), 0)
	return expirationTime, nil
}

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
