package symmetrictokenserviceencrypted

import (
	"errors"
	"fmt"
	"log"
	"reflect"
	"time"

	encryptdecrypt "github.com/GURUAKASHSM/Packages/TokenService/EncryptandDecryptToken"
	"github.com/golang-jwt/jwt/v4"
)

func CreateTokenWithStruct(data interface{}, SecretKey string, validtime int64, key []byte) (string, error) {
	log.Println("\n ****** Create Encrypted Token ****** ")

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

	encrypetedtoken, err := encryptdecrypt.EncryptToken(tokenString, key)
	if err != nil {
		return "", err
	}
	return encrypetedtoken, nil
}

func ExtractIDWithIDFeild(jwtToken string, secretKey string, key []byte, uniqueid string) (string, error) {
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
			id, ok := claims[uniqueid].(string)
			if ok {
				return id, nil
			}
		}
	}

	return "", fmt.Errorf("invalid or expired JWT token")
}

func GenerateAccessAndRefreshEncryptedTokensWithStruct(data interface{}, SecretKey string, key []byte) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Encrypted Token *****")

	accessToken, err := CreateTokenWithStruct(data, SecretKey, 1, key)
	if err != nil {
		log.Println(err)
		return "", "", err
	}

	refreshToken, err := CreateTokenWithStruct(data, SecretKey, 1*24*7, key)
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

