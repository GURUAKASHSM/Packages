package asymmetrictokenservice

import (
	"errors"
	"fmt"
	"log"
	"reflect"
	"time"

	encryptdecrypt "github.com/GURUAKASHSM/Packages/EncryptandDecryptToken"
	"github.com/dgrijalva/jwt-go"
)

func CreateEncrytedTokenWithKeyWithStruct(data interface{}, privateKeyBytes []byte, validtime int64,encryptionkey []byte) (string, error) {
	log.Println("\n ****** Create Encrypted Token with RSA ****** ")

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return "", err
	}

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

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	tokenString, err = encryptdecrypt.EncryptToken(tokenString,encryptionkey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ExtractIDFromEncrytedTokenWithKeyWithStruct(tokenString string, publicKeyBytes []byte,idfeildname string,decryptionkey []byte) (string, error) {
	log.Println("\n ****** Verify Token with RSA ****** ")

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return "", err
	}
    
	tokenString,err = encryptdecrypt.DecryptToken(tokenString,decryptionkey)
	if err != nil{
		return "",err
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

	id, ok := claims[idfeildname].(string)
	if !ok {
		return "", errors.New("feild name not found or not a string")
	}

	return id, nil
}

func GenerateAccessAndRefreshAsymmetricEncrytedTokensWithKeyWithStruct(data interface{}, privateKey []byte,encryptionkey []byte) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Asymmetric Tokens *****")

	accessToken, err := CreateEncrytedTokenWithKeyWithStruct(data, privateKey, 1,encryptionkey)
	if err != nil {
		log.Println("Error generating access token:", err)
		return "", "", err
	}

	refreshToken, err := CreateEncrytedTokenWithKeyWithStruct(data, privateKey, 7*24*1,encryptionkey)
	if err != nil {
		log.Println("Error generating refresh token:", err)
		return "", "", err
	}


	return accessToken, refreshToken, nil
}

func RefreshAsymmetricAccessEncrytedTokenWithKeyWithStruct(refreshToken string, publicKey, privateKey []byte,encryptionkey []byte) (string, error) {
	log.Println("\n ***** Refresh Access Asymmetric Token ***** ")

	claims, err := ExtractDetailsFromTokenWithKey(refreshToken, publicKey)
	if err != nil {
		return "", err
	}

	exp := int64(claims["exp"].(float64))
	if time.Now().Unix() > exp {
		return "", fmt.Errorf("refresh token has expired")
	}

	accessToken, err := CreateEncrytedTokenWithKeyWithStruct(claims, privateKey, 1,encryptionkey)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}
