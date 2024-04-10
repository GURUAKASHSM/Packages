package asymmetrictokenservice

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
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

// LoadRSAPrivateKey loads RSA private key from file
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// LoadRSAPublicKey loads RSA public key from file
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	keyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func CreateToken(email, id string, privateKeyPath string, validtime int64) (string, error) {
	log.Println("\n ****** Create Encrypted Token with RSA ****** ")

	privateKey, err := LoadRSAPrivateKey(privateKeyPath)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"email": email,
		"id":    id,
		"exp":   time.Now().Add(time.Hour * time.Duration(validtime)).Unix(),
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ExtractDetailsFromToken(tokenString string, publicKeyPath string) (jwt.MapClaims, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := LoadRSAPublicKey(publicKeyPath)
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

func ExtractIDFromToken(tokenString string, publicKeyPath string) (string, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		return "", err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", errors.New("invalid token or claims")
	}

	id, ok := claims["id"].(string)
	if !ok {
		return "", errors.New("id not found in claims or not a string")
	}

	return id, nil
}

// IsTokenValid checks if a token is valid or not
func IsTokenValid(tokenString string, publicKeyPath string) bool {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		log.Println("Error loading public key:", err)
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
func (tm *TokenManager) BlockToken(jwtToken, publicKeyPath string) error {
	log.Println("\n ****** Block Asymmetric Token ****** ")

	expirationTime, err := ExtractExpirationTimeFromToken(jwtToken, publicKeyPath)
	if err != nil {
		return err
	}

	publicKey, err := LoadRSAPublicKey(publicKeyPath)
	if err != nil {
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
func (tm *TokenManager) UnblockToken(jwtToken string, publicKeyPath string) error {
	log.Println("\n ****** Unblock Asymmetric Token ****** ")
	expirationTime, err := ExtractExpirationTimeFromToken(jwtToken, publicKeyPath)
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

func (tm *TokenManager) IsTokenBlocked(token string) bool {
	log.Println("\n ****** Is Asymmetric Token Blocked****** ")
	tm.revokedTokensMutex.RLock()
	defer tm.revokedTokensMutex.RUnlock()

	expirationTime, found := tm.revokedTokens[token]
	if !found {
		return false
	}

	return time.Now().Before(expirationTime)
}

func ExtractExpirationTimeFromToken(jwtToken string, publicKeyPath string) (time.Time, error) {
	log.Println("\n ***** Extract Expiration Time From Asymmetric Token ***** ")

	publicKey, err := LoadRSAPublicKey(publicKeyPath)
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

func GenerateAccessAndRefreshAsymmetricTokens(email, id, privateKeyPath, publicKeyPath string) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Asymmetric Tokens *****")

	accessToken, err := CreateToken(email, id, privateKeyPath, 1)
	if err != nil {
		log.Println("Error generating access token:", err)
		return "", "", err
	}

	refreshToken, err := CreateToken(email, id, privateKeyPath, 7*24*1)
	if err != nil {
		log.Println("Error generating refresh token:", err)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}


func RefreshAsymmetricAccessToken(refreshToken, publicKeyPath, privateKeyPath string) (string, error) {
	log.Println("\n ***** Refresh Access Asymmetric Token ***** ")

	claims, err := ExtractDetailsFromToken(refreshToken, publicKeyPath)
	if err != nil {
		return "", err
	}

	exp := int64(claims["exp"].(float64))
	if time.Now().Unix() > exp {
		return "", fmt.Errorf("refresh token has expired")
	}

	accessToken, err := CreateToken(claims["email"].(string), claims["id"].(string), privateKeyPath, 1)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}
