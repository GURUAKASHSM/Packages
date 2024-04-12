package asymmetrictokenservice

import (
	"errors"
	"fmt"
	"log"
	"time"

	encryptdecrypt "github.com/GURUAKASHSM/Packages/EncryptandDecryptToken"
	"github.com/dgrijalva/jwt-go"
)

func ExtractDetailsFromEncryptedTokenWithKey(tokenString string, publicKeyBytes []byte,decryptionkey []byte) (jwt.MapClaims, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	tokenString,err = encryptdecrypt.DecryptToken(tokenString,decryptionkey)
	if err != nil{
		return nil,err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// IsTokenValid checks if a token is valid or not
func IsEncryptedTokenValidWithKey(tokenString string, publicKeyBytes []byte,decryptionkey []byte) bool {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return false
	}

	tokenString,err = encryptdecrypt.DecryptToken(tokenString,decryptionkey)
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
func (tm *TokenManager) BlockEncryptedTokenWithKey(jwtToken string, publicKeyBytes []byte,decryptionkey []byte) error {
	log.Println("\n ****** Block Asymmetric Token ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return err
	}

	expirationTime, err := ExtractExpirationTimeFromEncryptedTokenWithKey(jwtToken, publicKeyBytes,decryptionkey)
	if err != nil {
		return err
	}

	jwtToken,err = encryptdecrypt.DecryptToken(jwtToken,decryptionkey)
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
func (tm *TokenManager) UnblockEncryptedTokenWithKey(jwtToken string, publicKeyBytes,decryptionkey []byte) error {
	log.Println("\n ****** Unblock Asymmetric Token ****** ")
	expirationTime, err := ExtractExpirationTimeFromEncryptedTokenWithKey(jwtToken, publicKeyBytes,decryptionkey)
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

func ExtractExpirationTimeFromEncryptedTokenWithKey(jwtToken string, publicKeyBytes,decryptionkey []byte) (time.Time, error) {
	log.Println("\n ***** Extract Expiration Time From Asymmetric Token ***** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return time.Time{}, err
	}

	jwtToken,err = encryptdecrypt.DecryptToken(jwtToken,decryptionkey)
	if err != nil{
		return time.Time{},err
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
