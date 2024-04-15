package symmetrictokenservicenonencrypted

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
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

func ExtractDetails(jwtToken string, secretKey string) (map[string]interface{}, error) {
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

func IsTokenValid(jwtToken, SecretKey string) bool {
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

// Define methods on MyTokenManager
func (tm *TokenManager) BlockToken(jwtToken, SecretKey string) error {
	log.Println("\n ****** Block NonEncrypted Token ****** ")

	expirationTime, err := ExtractExpirationTime(jwtToken)
	if err != nil {
		return err
	}

	tm.RevokedTokensMutex.Lock()
	defer tm.RevokedTokensMutex.Unlock()

	tm.RevokedTokens[jwtToken] = expirationTime

	return nil
}

func (tm *TokenManager) UnblockToken(jwtToken string) error {
	log.Println("\n ****** UnBlock NonEncrypted Token ****** ")
	expirationTime, err := ExtractExpirationTime(jwtToken)
	if err != nil {
		return err
	}
	tm.RevokedTokensMutex.Lock()
	defer tm.RevokedTokensMutex.Unlock()
	for token, exp := range tm.RevokedTokens {
		if exp.Equal(expirationTime) {
			delete(tm.RevokedTokens, token)
			return nil
		}
	}
	return fmt.Errorf("no token with expiration time '%s' is blocked", expirationTime)
}

func (tm *TokenManager) IsTokenBlocked(token string) bool {
	log.Println("\n ****** Is NonEncrypted Token Blocked****** ")
	tm.RevokedTokensMutex.RLock()
	defer tm.RevokedTokensMutex.RUnlock()

	expirationTime, found := tm.RevokedTokens[token]
	if !found {
		return false
	}

	return time.Now().Before(expirationTime)
}

func ExtractExpirationTime(jwtToken string) (time.Time, error) {
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

func RefreshAccessToken(refreshToken, SecretKey string) (string, error) {
	log.Println("\n ***** Refresh Access NonEncrypted Token ***** ")

	claims, err := ExtractDetails(refreshToken, SecretKey)
	if err != nil {
		return "", err
	}

	exp := int64(claims["exp"].(float64))
	if time.Now().Unix() > exp {
		return "", fmt.Errorf("refresh token has expired")
	}

	accessToken, err := CreateTokenWithStruct(claims, SecretKey, 1)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}
