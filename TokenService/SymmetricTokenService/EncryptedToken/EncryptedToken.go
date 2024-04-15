package symmetrictokenserviceencrypted

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	encryptdecrypt "github.com/GURUAKASHSM/Packages/TokenService/EncryptandDecryptToken"
	"github.com/golang-jwt/jwt/v4"
	typeconversionservice "github.com/GURUAKASHSM/Packages/TypeConversionService"
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

func ExtractDetails(jwtToken string, secretKey string, key []byte) (map[string]interface{}, error) {
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

func IsTokenValid(jwtToken, SecretKey string, key []byte) (bool, error) {
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

func (tm *TokenManager) BlockToken(token string, key []byte) error {
	log.Println("\n ****** Block Encrypted Token ****** ")

	expirationTime, err := ExtractExpirationTime(token, key) // Fix here
	if err != nil {
		return err
	}

	decryptedToken, err := encryptdecrypt.DecryptToken(token, key)
	if err != nil {
		return err
	}

	tm.RevokedTokensMutex.Lock()
	defer tm.RevokedTokensMutex.Unlock()

	tm.RevokedTokens[decryptedToken] = expirationTime // Fix here

	return nil
}

func (tm *TokenManager) UnblockToken(encryptedToken, SecretKey string, key []byte) error {
	log.Println("\n ****** UnBlock Encrypted Token ****** ")

	expirationTime, err := ExtractExpirationTime(encryptedToken, key)
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

func (tm *TokenManager) IsTokenBlocked(token string, key []byte) (bool, error) {
	log.Println("\n ****** Is Encrypted Token Blocked****** ")
	decryptedToken, err := encryptdecrypt.DecryptToken(token, key)
	if err != nil {
		return false, err
	}
	tm.RevokedTokensMutex.RLock()
	defer tm.RevokedTokensMutex.RUnlock()

	expirationTime, found := tm.RevokedTokens[decryptedToken]
	if !found {
		return false, nil
	}

	return time.Now().Before(expirationTime), nil
}

func ExtractExpirationTime(jwtToken string, key []byte) (time.Time, error) {
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

func RefreshAccessToken(refreshToken, SecretKey string, key []byte) (string, error) {
	log.Println("\n ***** Refresh Access Encrypted Token ***** ")

	claims, err := ExtractDetails(refreshToken, SecretKey, key)
	if err != nil {
		return "", err
	}

	exp := int64(claims["exp"].(float64))
	if time.Now().Unix() > exp {
		return "", fmt.Errorf("refresh token has expired")
	}

	data, err := typeconversionservice.MapToStruct(claims)
	if err != nil {
		log.Println(err)
		return "", err
	}

	accessToken, err := CreateTokenWithStruct(data, SecretKey, 1, key)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}
