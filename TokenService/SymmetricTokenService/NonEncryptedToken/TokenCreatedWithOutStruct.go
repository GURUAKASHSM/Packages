package symmetrictokenservicenonencrypted

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func CreateToken(email, id, SecretKey string, validtime int64) (string, error) {
	log.Println("\n ****** Create NonEncrypted Token ****** ")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"id":    id,
		"exp":   time.Now().Add(time.Hour * time.Duration(validtime)).Unix(),
	})

	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ExtractID(jwtToken string, secretKey string) (string, error) {
	log.Println("\n ****** Extract ID Form NonEncrypted Token ****** ")
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {

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

func GenerateAccessAndRefreshTokens(email, id, SecretKey string) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh NonEncrypted Token *****")

	accessToken, err := CreateToken(email, id, SecretKey, 1)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	refreshToken, err := CreateToken(email, id, SecretKey, 1*24*7)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}


