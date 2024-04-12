package symmetrictokenservice

import (
	"errors"
	"fmt"
	"log"
	"time"

	encryptdecrypt "github.com/GURUAKASHSM/Packages/EncryptandDecryptToken"
	"github.com/golang-jwt/jwt/v4"
)

func ExtractDetailsFromEncryptedToken(jwtToken string, secretKey string, key []byte) (map[string]interface{}, error) {
	log.Println("\n ****** Extract Details Form Encrypted Token ****** ")

	decryptedToken, err := encryptdecrypt.DecryptToken(jwtToken, key)
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

	decryptedToken, err := encryptdecrypt.DecryptToken(jwtToken, key)
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

	decryptedToken, err := encryptdecrypt.DecryptToken(token, key)
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

func (tm *TokenManager) UnblockEncryptedToken(encryptedToken, SecretKey string, key []byte) error {
	log.Println("\n ****** UnBlock Encrypted Token ****** ")

	// Decrypt the token to extract its contents
	decryptedToken, err := encryptdecrypt.DecryptToken(encryptedToken, key)
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
	decryptedToken, err := encryptdecrypt.DecryptToken(token, key)
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

func ExtractExpirationTimeFromEncryptedToken(jwtToken string, key []byte) (time.Time, error) {
	log.Println("\n ***** Extract Expiration Time From Encrypted Token ***** ")

	decryptedToken, err := encryptdecrypt.DecryptToken(jwtToken, key)
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
