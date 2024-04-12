package symmetrictokenservice

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type TokenManager struct {
	revokedTokens      map[string]time.Time
	revokedTokensMutex sync.RWMutex
}

func NewTokenManager() *TokenManager {
	return &TokenManager{
		revokedTokens: make(map[string]time.Time),
	}
}

func ExtractDetailsFromToken(jwtToken string, secretKey string) (map[string]interface{}, error) {
	log.Println("\n ****** Extract Details Form NonEncrypted Token ****** ")
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
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

func Validatetoken(jwtToken, SecretKey string) bool {
	log.Println("\n ****** Validate NonEncrypted Token ****** ")
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(SecretKey), nil
	})

	if err != nil {
		log.Println(err)
		return false
	}

	if token.Valid {
		return true
	}

	return false
}
func (tm *TokenManager) BlockToken(jwtToken, SecretKey string) error {
	log.Println("\n ****** Block NonEncrypted Token ****** ")

	expirationTime, err := ExtractExpirationTimeFromToken(jwtToken) // Fix here
	if err != nil {
		return err
	}

	tm.revokedTokensMutex.Lock()
	defer tm.revokedTokensMutex.Unlock()

	tm.revokedTokens[jwtToken] = expirationTime // Fix here

	return nil
}

func (tm *TokenManager) UnblockToken(jwtToken string) error {
	log.Println("\n ****** UnBlock NonEncrypted Token ****** ")
	expirationTime, err := ExtractExpirationTimeFromToken(jwtToken)
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

func (tm *TokenManager) IsTokenBlocked(token string) bool {
	log.Println("\n ****** Is NonEncrypted Token Blocked****** ")
	tm.revokedTokensMutex.RLock()
	defer tm.revokedTokensMutex.RUnlock()

	expirationTime, found := tm.revokedTokens[token]
	if !found {
		return false
	}

	return time.Now().Before(expirationTime)
}

func ExtractExpirationTimeFromToken(jwtToken string) (time.Time, error) {
	log.Println("\n ***** Extract Expiration Time From NonEncryptedToken ***** ")

	token, _, err := new(jwt.Parser).ParseUnverified(jwtToken, jwt.MapClaims{})
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

	// Convert exp claim from Unix timestamp to time.Time
	expirationTime := time.Unix(int64(expClaim), 0)
	return expirationTime, nil
}
