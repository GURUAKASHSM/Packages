package asymmetrictokenserviceencryptedwithkeypath

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
	typeconversionservice "github.com/GURUAKASHSM/Packages/TypeConversionService"

	asymmetrictokenservice "github.com/GURUAKASHSM/Packages/TokenService/AsymmetricTokenService"
	encryptdecrypt "github.com/GURUAKASHSM/Packages/TokenService/EncryptandDecryptToken"
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

func ExtractDetails(tokenString string, publicKeyPath string, decryptionkey []byte) (jwt.MapClaims, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := asymmetrictokenservice.LoadRSAPublicKey(publicKeyPath)
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
func IsTokenValid(tokenString string, publicKeyPath string, decryptionkey []byte) bool {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := asymmetrictokenservice.LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		log.Println("Error loading public key:", err)
		return false
	}

	tokenString, err = encryptdecrypt.DecryptToken(tokenString, decryptionkey)
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
func (tm *TokenManager) BlockToken(jwtToken, publicKeyPath string, decryptionkey []byte) error {
	log.Println("\n ****** Block Asymmetric Token ****** ")

	expirationTime, err := ExtractExpirationTime(jwtToken, publicKeyPath, decryptionkey)
	if err != nil {
		return err
	}

	publicKey, err := asymmetrictokenservice.LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		return err
	}

	jwtToken, err = encryptdecrypt.DecryptToken(jwtToken, decryptionkey)
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
func (tm *TokenManager) UnblockToken(jwtToken string, publicKeyPath string, decryptionkey []byte) error {
	log.Println("\n ****** Unblock Asymmetric Token ****** ")

	expirationTime, err := ExtractExpirationTime(jwtToken, publicKeyPath, decryptionkey)
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

func (tm *TokenManager) IsTokenBlocked(token string, decryptionkey []byte) bool {
	log.Println("\n ****** Is Asymmetric Token Blocked****** ")

	token, err := encryptdecrypt.DecryptToken(token, decryptionkey)
	if err != nil {
		return false
	}

	tm.RevokedTokensMutex.RLock()
	defer tm.RevokedTokensMutex.RUnlock()

	expirationTime, found := tm.RevokedTokens[token]
	if !found {
		return false
	}

	return time.Now().Before(expirationTime)
}

func ExtractExpirationTime(jwtToken string, publicKeyPath string, decryptionkey []byte) (time.Time, error) {
	log.Println("\n ***** Extract Expiration Time From Asymmetric Token ***** ")

	publicKey, err := asymmetrictokenservice.LoadRSAPublicKey(publicKeyPath)
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

func RefreshAccessToken(refreshToken, publicKeyPath, privateKeyPath string,decryptionkey []byte) (string, error) {
	log.Println("\n ***** Refresh Access Asymmetric Token ***** ")

	claims, err := ExtractDetails(refreshToken, publicKeyPath,decryptionkey)
	if err != nil {
		return "", err
	}

	exp := int64(claims["exp"].(float64))
	if time.Now().Unix() > exp {
		return "", fmt.Errorf("refresh token has expired")
	}

	data,err  := typeconversionservice.MapToStruct(claims)
	if err != nil{
		log.Println(err)
		return "",err
	}

	accessToken, err := CreateTokenWithStruct(data, privateKeyPath, 1,decryptionkey)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}
