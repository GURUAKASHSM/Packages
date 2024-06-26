package symmetrictokenserviceencrypted

import (
	"fmt"
	"log"
	"time"

	encryptdecrypt "github.com/GURUAKASHSM/Packages/TokenService/EncryptandDecryptToken"
	"github.com/golang-jwt/jwt/v4"
)

func CreateToken(email, id, SecretKey string, validtime int64, key []byte) (string, error) {
	log.Println("\n ****** Create Encrypted Token ****** ")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"id":    id,
		"exp":   time.Now().Add(time.Hour * time.Duration(validtime)).Unix(),
	})

	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return "", err
	}
	encrypetedtoken, err := encryptdecrypt.EncryptToken(tokenString, key)
	if err != nil {
		return "", err
	}
	return encrypetedtoken, nil
}

func ExtractID(jwtToken string, secretKey string, key []byte) (string, error) {
	log.Println("\n ****** Extract ID From Encrypted Token ****** ")

	decryptedToken, err := encryptdecrypt.DecryptToken(jwtToken, key)
	if err != nil {
		return "", err
	}

	token, err := jwt.Parse(decryptedToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		log.Println(err)
		return "", err
	}

	if token.Valid {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			id, ok := claims["id"].(string)
			if ok {
				return id, nil
			}
		}
	}

	return "", fmt.Errorf("invalid or expired JWT token")
}

func GenerateAccessAndRefreshTokens(email, id, SecretKey string, key []byte) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Encrypted Token *****")

	accessToken, err := CreateToken(email, id, SecretKey, 1,key)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	refreshToken, err := CreateToken(email, id, SecretKey, 1*24*7,key)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	accessToken, err = encryptdecrypt.EncryptToken(accessToken, key)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = encryptdecrypt.EncryptToken(refreshToken, key)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}


