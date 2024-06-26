package main

import (
	"time"

	"github.com/GURUAKASHSM/Packages/Protogen"
)

type Person struct {
	ID           string                 `validate:"required,uuid4"`
	FirstName    string                 `json:"first_name" bson:"first_name" validate:"required,alpha"`
	LastName     string                 `json:"last_name" bson:"last_name" validate:"required,alpha"`
	Age          int                    `json:"age" bson:"age" validate:"required,gte=0,lte=130"`
	Email        string                 `json:"email" bson:"email" validate:"required,email"`
	CreatedAt    time.Time              `json:"created_at" bson:"created_at" validate:"required"`
	Active       bool                   `json:"active" bson:"active" validate:"required"`
	PhoneNumbers []string               `json:"phone_numbers" bson:"phone_numbers" validate:"dive,e164"`
	Address      map[string]string      `json:"address" bson:"address" validate:"required,dive,keys,required,endkeys,required"`
	Preferences  map[string]interface{} `json:"preferences" bson:"preferences"`
	Balance      float64                `json:"balance" bson:"balance" validate:"required,gte=0"`
	Score        *int                   `json:"score,omitempty" bson:"score,omitempty" validate:"omitempty,gte=0"`
}

func main() {
	var gen Person
	Protogen.GenerateProto(gen)
	// service_test.RunAllTests()
	// token, err := asymmetrictokenservice.CreateToken("guruakash.ec20@bitsathy.ac.in", "123231324", "decrypted_private_key.pem", 1)
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// log.Println("token", token)

	// data1, err := asymmetrictokenservice.ExtractDetails(token, "public_key.pem")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// log.Println("details", data1)

	// id, err := asymmetrictokenservice.ExtractID(token, "public_key.pem")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// log.Println("details", id)

	// valid := asymmetrictokenservice.IsTokenValid(token, "public_key.pem")
	// log.Println("vaild", valid)

	// tokenManager := asymmetrictokenservice.NewTokenManager()

	// err = tokenManager.BlockToken(token, "public_key.pem")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }

	// valid = tokenManager.IsTokenBlocked(token)
	// log.Println("Isblocked", valid)

	// err = tokenManager.UnblockToken(token, "public_key.pem")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }

	// valid = tokenManager.IsTokenBlocked(token)
	// log.Println("Isblocked", valid)

	// time, err := asymmetrictokenservice.ExtractExpirationTime(token, "public_key.pem")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// log.Println("ValidTill", time)

	// accesstoken, refreshtoken, err := asymmetrictokenservice.GenerateAccessAndRefreshTokens("gurakash.ec20@bitsathy.ac.in", "12132434345swf121", "decrypted_private_key.pem", "public_key.pem")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// log.Println("accesstoken", accesstoken)
	// log.Println("refreshtoken", refreshtoken)

	// accesstoken, err = asymmetrictokenservice.RefreshAccessToken(refreshtoken, "public_key.pem", "decrypted_private_key.pem")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }
	// log.Println("accesstoken", accesstoken)

	//privatekey := []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqBRW3G70Cd1vz\n2eNlSTyuxZngqg7kIACJpH0Q3Ko0VecHYyY8RqlRQbYtRLw0Z+jRQyXXFQV3Lqzh\nq2mXPRElNAgyqv5XCdv8+bANqrd70XbGHD3IAofLQg4H+NAuhR6ijvOnO7O0KSKM\nZAozO5DalnPmD8xz4WSA65M7KQfZpW/HijRU6EWQr5ntfEOvrVte9B/0oo2fsZDS\nNASn3DUwYD3qcMFhxUzO2JR/M/fKVMn1nDXMtif5p1R1MoP6xn1zKaHGf5BWaI+c\ns2rmiazoOg9smULKNZ/YnZMWnJwBlKr/eGLokJPFgSPg35Kj1qJQ9mNYOplOae/q\n+C8P8qetAgMBAAECggEABF4BEdm5nFibXOF0RJDyyuoBpyj+pHTDKSBOSWZcAdEV\nanmh3epDNm7/6Pa1f1z/OK0WK6BKQPHSVk++ocdMYCb48UnjXtfNoydqCxsfJRUP\n9q4R2ovY6sHoblvBcPngv7CtgzDj3pNOglklnTix4ouCkiYoVA1yNTZ9iRZu9U40\nNgq+SgKOPLDpnQEj05xHO1blSRnefUeQRoLrPYQxe9iCosNKBuglwenmTLSSZCBz\n0GsmcmEakeu6uxKNWknFNcGZ6lQaD0OBo4LtkgBE6D1F27haEb+KSgZ1z9ep//KQ\nXlMrFoNtNGtScjZIIImDSrnLIs1AuYlXEbmfoR1lmQKBgQDNikaXk908iqLmnHZh\nd64OLLryRg3cWc09uQm9Ye7j6v+wbm0uzffwSsc2Y1/D2JBFdYHHbmcROGJfLaab\nfQ0R9AjonNXXlo9zC9O6s+q4ZJe59Fy3zRce5lWTYJ99ZYsVQdZFpuXuxGYuOUnm\n5C4aqhE/MOUPggZRsBSBBNaRLwKBgQDTwnEFyLJ5S70OzhKe7K3FKKHjT2w7ZP76\nYlYBbsS7aVIc9EmezYJntM0LvJtJUzdL2c3sbV6rqmUm6XXWePSgHS1nd0npL9to\nUmuOK9Q0Ce5fewyXeq7JoaQAHLVLQKeezS3lLm1gIVFy3zQ0JiyEyfUDd0z8pRdL\nCWMtvkYF4wKBgAdERTykqKS0ThATJghKH+g2YqGgImtQ7XWqLhL4/GYob8PAE7Ic\n7BAdxK9CkictZ+RcxCrV12T/dlLhHUvP/v9Mfmgi61iE5StvFpw6Mik0vTyAzCpf\nYNrhz9K3DsxzI5irzDSIMwbfALHPqrI0DQE6VAPE6cRDl4+Zxw/MqP1XAoGAUQmA\nJy5+3lxVpWzHQ3pfpau/CDZEvRYRXdB0CWhScUYE3n++DL+ov/c44Nz0sELgTm6z\nl17jc95ph1KgfcscEooX7hiAeHSQCoRAFNBBDQkf5/o2/2E7sn3hPQm/d2TuwJ7U\niXgS807M1KEGYU6aitaepQzqsWScXWLiSYcfVPECgYEAx3jWUKH+rO4t7A9w8I1r\nMyjBmIN+YV8VLM7KiXnO71dVkyx/MiLGGnsoTZz/Qyriur3MV9hnwJQNMcD6eLA1\nixw4V8rS3jEmDJXZw/7LteP24aPqUrq0mTunOt4OLgWeoGs5e8cEIQdkQ+o0t3ZV\nEI994zyXzNrtQ5Ad1swUMBA=\n-----END PRIVATE KEY-----")

}
