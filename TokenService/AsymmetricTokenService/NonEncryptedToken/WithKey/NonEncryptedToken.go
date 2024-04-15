package asymmetrictokenservicenonencryptedwithkey

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type TokenManager struct {
	RevokedTokens      map[string]time.Time
	RevokedTokensMutex sync.RWMutex
}

func NewTokenManager() *TokenManager {
	return &TokenManager{
		RevokedTokens: make(map[string]time.Time),
	}
}

func ExtractDetails(tokenString string, publicKeyBytes []byte) (jwt.MapClaims, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
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
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// IsTokenValid checks if a token is valid or not
func IsTokenValid(tokenString string, publicKeyBytes []byte) bool {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
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
func (tm *TokenManager) BlockToken(jwtToken string, publicKeyBytes []byte) error {
	log.Println("\n ****** Block Asymmetric Token ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return err
	}

	expirationTime, err := ExtractExpirationTime(jwtToken, publicKeyBytes)
	if err != nil {
		return err
	}

	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		return errors.New("invalid token")
	}

	tm.RevokedTokensMutex.Lock()
	defer tm.RevokedTokensMutex.Unlock()

	tm.RevokedTokens[jwtToken] = expirationTime

	return nil
}

// UnblockAsymmetricToken unblocks an asymmetrically encrypted token
func (tm *TokenManager) UnblockToken(jwtToken string, publicKeyBytes []byte) error {
	log.Println("\n ****** Unblock Asymmetric Token ****** ")
	expirationTime, err := ExtractExpirationTime(jwtToken, publicKeyBytes)
	if err != nil {
		return err
	}

	tm.RevokedTokensMutex.Lock()
	defer tm.RevokedTokensMutex.Unlock()

	// Iterate through blocked tokens and remove the one with the matching expiration time
	for token, exp := range tm.RevokedTokens {
		if exp.Equal(expirationTime) {
			delete(tm.RevokedTokens, token)
			return nil
		}
	}
	return fmt.Errorf("no token with expiration time '%s' is blocked", expirationTime)
}

func ExtractExpirationTime(jwtToken string, publicKeyBytes []byte) (time.Time, error) {
	log.Println("\n ***** Extract Expiration Time From Asymmetric Token ***** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
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
