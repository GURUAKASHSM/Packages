package asymmetrictokenserviceencryptedwithkeypath

import (
	"errors"
	"log"
	"time"

	asymmetrictokenservice "github.com/GURUAKASHSM/Packages/TokenService/AsymmetricTokenService"
	encryptdecrypt "github.com/GURUAKASHSM/Packages/TokenService/EncryptandDecryptToken"
	"github.com/dgrijalva/jwt-go"
)

func CreateToken(email, id string, privateKeyPath string, validtime int64, encryptionkey []byte) (string, error) {
	log.Println("\n ****** Create Encrypted Token with RSA ****** ")

	privateKey, err := asymmetrictokenservice.LoadRSAPrivateKey(privateKeyPath)
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

	tokenString, err = encryptdecrypt.EncryptToken(tokenString, encryptionkey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ExtractID(tokenString string, publicKeyPath string, decryptionkey []byte) (string, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := asymmetrictokenservice.LoadRSAPublicKey(publicKeyPath)
	if err != nil {
		return "", err
	}

	tokenString, err = encryptdecrypt.DecryptToken(tokenString, decryptionkey)
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

func GenerateAccessAndRefreshTokens(email, id, privateKeyPath, publicKeyPath string, encryptionkey []byte) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Asymmetric Tokens *****")

	accessToken, err := CreateToken(email, id, privateKeyPath, 1, encryptionkey)
	if err != nil {
		log.Println("Error generating access token:", err)
		return "", "", err
	}

	refreshToken, err := CreateToken(email, id, privateKeyPath, 7*24*1, encryptionkey)
	if err != nil {
		log.Println("Error generating refresh token:", err)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
