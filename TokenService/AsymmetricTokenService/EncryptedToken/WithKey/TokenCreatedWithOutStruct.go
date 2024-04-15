package asymmetrictokenserviceencryptedwithkey

import (
	"errors"
	"log"
	"time"

	encryptdecrypt "github.com/GURUAKASHSM/Packages/TokenService/EncryptandDecryptToken"
	"github.com/dgrijalva/jwt-go"
)

func CreateToken(email, id string, privateKeyBytes []byte, validtime int64, encryptionkey []byte) (string, error) {
	log.Println("\n ****** Create Encrypted Token with RSA ****** ")

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
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

func ExtractID(tokenString string, publicKeyBytes []byte, decryptionkey []byte) (string, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
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

func GenerateAccessAndRefreshTokens(email string, id string, privateKey, publicKey []byte, encryptionkey []byte) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Asymmetric Tokens *****")

	accessToken, err := CreateToken(email, id, privateKey, 1, encryptionkey)
	if err != nil {
		log.Println("Error generating access token:", err)
		return "", "", err
	}

	refreshToken, err := CreateToken(email, id, privateKey, 7*24*1, encryptionkey)
	if err != nil {
		log.Println("Error generating refresh token:", err)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// func RefreshAccessToken(refreshToken string, publicKey, privateKey []byte,encryptionkey []byte) (string, error) {
// 	log.Println("\n ***** Refresh Access Asymmetric Token ***** ")

// 	claims, err := ExtractDetails(refreshToken, publicKey,encryptionkey)
// 	if err != nil {
// 		return "", err
// 	}

// 	exp := int64(claims["exp"].(float64))
// 	if time.Now().Unix() > exp {
// 		return "", fmt.Errorf("refresh token has expired")
// 	}

// 	accessToken, err := CreateToken(claims["email"].(string), claims["id"].(string), privateKey, 1,encryptionkey)
// 	if err != nil {
// 		return "", err
// 	}

// 	return accessToken, nil
// }
