package asymmetrictokenservice

import (
	"errors"
	"fmt"
	"log"
	"time"

	encryptdecrypt "github.com/GURUAKASHSM/Packages/EncryptandDecryptToken"
	"github.com/dgrijalva/jwt-go"
)

func ExtractDetailsFromEncryptedTokenWithKeyPath(tokenString string, publicKeyPath string, decryptionkey []byte) (jwt.MapClaims, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		return nil, err
	}

	tokenString, err = encryptdecrypt.DecryptToken(tokenString, decryptionkey)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}

	return claims, nil
}

// IsTokenValid checks if a token is valid or not
func IsEncryptedTokenValidWithKeyPath(tokenString string, publicKeyPath string, decryptionkey []byte) bool {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		log.Println("Error loading public key:", err)
		return false
	}

	tokenString, err = encryptdecrypt.DecryptToken(tokenString, decryptionkey)
	if err != nil{
		return false
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		log.Println("Invalid token:", err)
		return false
	}

	return true
}

// BlockToken blocks an asymmetrically encrypted token
func (tm *TokenManager) BlockEncryptedTokenWithKeyPath(jwtToken, publicKeyPath string, decryptionkey []byte) error {
	log.Println("\n ****** Block Asymmetric Token ****** ")

	expirationTime, err := ExtractExpirationTimeFromEncryptedTokenWithKeyPath(jwtToken, publicKeyPath,decryptionkey)
	if err != nil {
		return err
	}

	publicKey, err := LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		return err
	}

	jwtToken, err = encryptdecrypt.DecryptToken(jwtToken, decryptionkey)
	if err != nil{
		return err
	}

	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		return errors.New("invalid token")
	}

	tm.revokedTokensMutex.Lock()
	defer tm.revokedTokensMutex.Unlock()

	tm.revokedTokens[jwtToken] = expirationTime

	return nil
}

// UnblockAsymmetricToken unblocks an asymmetrically encrypted token
func (tm *TokenManager) UnblockEncryptedTokenWithKeyPath(jwtToken string, publicKeyPath string,decryptionkey []byte) error {
	log.Println("\n ****** Unblock Asymmetric Token ****** ")

	expirationTime, err := ExtractExpirationTimeFromEncryptedTokenWithKeyPath(jwtToken, publicKeyPath,decryptionkey)
	if err != nil {
		return err
	}

	tm.revokedTokensMutex.Lock()
	defer tm.revokedTokensMutex.Unlock()

	// Iterate through blocked tokens and remove the one with the matching expiration time
	for token, exp := range tm.revokedTokens {
		if exp.Equal(expirationTime) {
			delete(tm.revokedTokens, token)
			return nil
		}
	}
	return fmt.Errorf("no token with expiration time '%s' is blocked", expirationTime)
}

func (tm *TokenManager) IsEncryptedTokenBlocked(token string,decryptionkey []byte) bool {
	log.Println("\n ****** Is Asymmetric Token Blocked****** ")

	token, err := encryptdecrypt.DecryptToken(token, decryptionkey)
	if err != nil{
		return false
	}

	tm.revokedTokensMutex.RLock()
	defer tm.revokedTokensMutex.RUnlock()

	expirationTime, found := tm.revokedTokens[token]
	if !found {
		return false
	}

	return time.Now().Before(expirationTime)
}

func ExtractExpirationTimeFromEncryptedTokenWithKeyPath(jwtToken string, publicKeyPath string, decryptionkey []byte) (time.Time, error) {
	log.Println("\n ***** Extract Expiration Time From Asymmetric Token ***** ")

	publicKey, err := LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		return time.Time{}, err
	}

	jwtToken, err = encryptdecrypt.DecryptToken(jwtToken, decryptionkey)
	if err != nil {
		return time.Time{}, err
	}

	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return time.Time{}, err
	}

	if !token.Valid {
		return time.Time{}, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return time.Time{}, errors.New("invalid token claims")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, errors.New("expiration time (exp) claim not found or invalid")
	}

	expirationTime := time.Unix(int64(exp), 0)
	return expirationTime, nil
}
