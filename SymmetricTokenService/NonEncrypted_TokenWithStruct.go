package symmetrictokenservice

import (
	"errors"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func CreateTokenWithStruct(data interface{}, SecretKey string, validtime int64) (string, error) {
	log.Println("\n ****** Create NonEncrypted Token ****** ")

	result := make(map[string]interface{})

	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Struct {
		return "", errors.New("data is not a struct")
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json") // Get JSON tag
		if tag != "" {
			result[tag] = val.Field(i).Interface() // Set field value to map
		}
	}

	claims := jwt.MapClaims{}
	for key, value := range result {
		claims[key] = value
	}
	claims["exp"] = time.Now().Add(time.Hour * time.Duration(validtime)).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	
	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func GenerateAccessAndRefreshTokensWithStruct(data interface{}, SecretKey string) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh NonEncrypted Token *****")

	accessToken, err := CreateTokenWithStruct(data, SecretKey, 1)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	refreshToken, err := CreateTokenWithStruct(data, SecretKey, 1*24*7)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func RefreshAccessTokenCreatedWithStruct(refreshToken, SecretKey string) (string, error) {
	log.Println("\n ***** Refresh Access NonEncrypted Token ***** ")

	claims, err := ExtractDetailsFromToken(refreshToken, SecretKey)
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

func ExtractIDFromTokenCreatedWithStruct(jwtToken string, secretKey string,uniqueidname string) (string, error) {
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
			id, ok := claims[uniqueidname].(string)
			if ok {
				return id, nil
			}
		}
	}

	return "", fmt.Errorf("invalid or expired JWT token")
}
