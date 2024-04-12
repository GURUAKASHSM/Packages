package asymmetrictokenservice

import (
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
