package asymmetrictokenserviceencryptedwithkeypath

import (
	"errors"
	"log"
	"reflect"
	"time"

	asymmetrictokenservice "github.com/GURUAKASHSM/Packages/TokenService/AsymmetricTokenService"
	encryptdecrypt "github.com/GURUAKASHSM/Packages/TokenService/EncryptandDecryptToken"
	"github.com/dgrijalva/jwt-go"
)

func CreateTokenWithStruct(data interface{}, privateKeyPath string, validtime int64, encryptionkey []byte) (string, error) {
	log.Println("\n ****** Create Encrypted Token with RSA ****** ")

	privateKey, err := asymmetrictokenservice.LoadRSAPrivateKey(privateKeyPath)
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

	tokenString, err = encryptdecrypt.EncryptToken(tokenString, encryptionkey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ExtractIDWithStructFeild(tokenString string, publicKeyPath string, idname string, decryptionkey []byte) (string, error) {
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

	id, ok := claims[idname].(string)
	if !ok {
		return "", errors.New("id not found in claims or not a string")
	}

	return id, nil
}

func GenerateAccessAndRefreshTokensWithStruct(data interface{}, privateKeyPath, publicKeyPath string, encryptionkey []byte) (string, string, error) {
	log.Println("\n ***** Generate Access and Refresh Asymmetric Tokens *****")

	accessToken, err := CreateTokenWithStruct(data, privateKeyPath, 1, encryptionkey)
	if err != nil {
		log.Println("Error generating access token:", err)
		return "", "", err
	}

	refreshToken, err := CreateTokenWithStruct(data, privateKeyPath, 7*24*1, encryptionkey)
	if err != nil {
		log.Println("Error generating refresh token:", err)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
