package symmetrictokenserviceencrypted

import (
	"fmt"
	"log"
	"time"

	encryptdecrypt "github.com/GURUAKASHSM/Packages/TokenService/EncryptandDecryptToken"
	"github.com/golang-jwt/jwt/v4"
)

func CreateEncryptedToken(email, id, SecretKey string, validtime int64, key []byte) (string, error) {
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

func ExtractIdFromEncryptedToken(jwtToken string, secretKey string, key []byte) (string, error) {
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

func GenerateAccessAndRefreshEncryptedTokens(email, id, SecretKey string, key []byte) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Encrypted Token *****")

	accessToken, err := CreateEncryptedToken(email, id, SecretKey, 1,key)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	refreshToken, err := CreateEncryptedToken(email, id, SecretKey, 1*24*7,key)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func RefreshAccessEncryptedToken(refreshToken, SecretKey string, key []byte) (string, error) {
	log.Println("\n ***** Refresh Access Encrypted Token ***** ")

	decryptedToken, err := encryptdecrypt.DecryptToken(refreshToken, key)
	if err != nil {
		return "", err
	}

	claims, err := ExtractDetailsFromToken(decryptedToken, SecretKey)
	if err != nil {
		return "", err
	}

	exp := int64(claims["exp"].(float64))
	if time.Now().Unix() > exp {
		return "", fmt.Errorf("refresh token has expired")
	}

	accessToken, err := CreateEncryptedToken(claims["email"].(string), claims["id"].(string), SecretKey, 1,key)
	if err != nil {
		return "", err
	}



	return accessToken, nil
}
