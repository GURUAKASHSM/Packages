package asymmetrictokenservice

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func CreateTokenWithKeyPath(email, id string, privateKeyPath string, validtime int64) (string, error) {
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

func ExtractIDFromTokenWithKeyPath(tokenString string, publicKeyPath string) (string, error) {
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

func GenerateAccessAndRefreshAsymmetricTokensWithKeyPath(email, id, privateKeyPath, publicKeyPath string) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Asymmetric Tokens *****")

	accessToken, err := CreateTokenWithKeyPath(email, id, privateKeyPath, 1)
	if err != nil {
		log.Println("Error generating access token:", err)
		return "", "", err
	}

	refreshToken, err := CreateTokenWithKeyPath(email, id, privateKeyPath, 7*24*1)
	if err != nil {
		log.Println("Error generating refresh token:", err)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func RefreshAsymmetricAccessTokenWithKeyPath(refreshToken, publicKeyPath, privateKeyPath string) (string, error) {
	log.Println("\n ***** Refresh Access Asymmetric Token ***** ")

	claims, err := ExtractDetailsFromTokenWithKeyPath(refreshToken, publicKeyPath)
	if err != nil {
		return "", err
	}

	exp := int64(claims["exp"].(float64))
	if time.Now().Unix() > exp {
		return "", fmt.Errorf("refresh token has expired")
	}

	accessToken, err := CreateTokenWithKeyPath(claims["email"].(string), claims["id"].(string), privateKeyPath, 1)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}
