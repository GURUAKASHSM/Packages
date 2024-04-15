package service_test

import (
	"log"
	"testing"


    
	encryptdecrypt "github.com/GURUAKASHSM/Packages/TokenService/EncryptandDecryptToken"
	service "github.com/GURUAKASHSM/Packages/TokenService/SymmetricTokenService/EncryptedToken"
)

func TestCreateEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"
	validtime := int64(1)
	key := []byte("1234567890123456")

	encryptedToken, err := service.CreateToken(email, id, SecretKey, validtime, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	if encryptedToken == "" {
		t.Error("Encrypted token creation failed")
	}
	log.Println("\n \n TestCreateEncryptedToken")
}

func TestCreateEncryptedTokenWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	type Test struct{
		Email string `json:"email" bson:"email"`
		Id string `json:"id" bson:"id"`
	}
	var data  Test
	data.Email = "guruakash.ec20@bitsathy.ac.in"
	data.Id = "123456"
	validtime := int64(1)
	key := []byte("1234567890123456")

	encryptedToken, err := service.CreateTokenWithStruct(data, SecretKey, validtime, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	if encryptedToken == "" {
		t.Error("Encrypted token creation failed")
	}
	log.Println("\n \n TestCreateEncryptedToken")
}

func TestExtractIdFromEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	id := "123456"
	key := []byte("1234567890123456")
	

	token, err := service.CreateToken("guruakash.ec20@bitsathy.ac.in", id, SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	extractedID, err := service.ExtractID(token, SecretKey, key)
	if err != nil {
		t.Errorf("Error extracting ID from encrypted token: %v", err)
	}

	if extractedID != id {
		t.Errorf("Expected ID: %s, Got: %s", id, extractedID)
	}
	log.Println("\n \n TestExtractIdFromEncryptedToken")

}


func TestExtractIdFromEncryptedTokenWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	
	key := []byte("1234567890123456")

	type Test struct{
		Email string `json:"email" bson:"email"`
		Id string `json:"id" bson:"id"`
	}
	var data  Test
	data.Email = "guruakash.ec20@bitsathy.ac.in"
	data.Id = "123456"

	token, err := service.CreateTokenWithStruct(data, SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}


	extractedID, err := service.ExtractIDWithIDFeild(token, SecretKey, key,"id")
	if err != nil {
		t.Errorf("Error extracting ID from encrypted token: %v", err)
	}

	if extractedID != data.Id {
		t.Errorf("Expected ID: %s, Got: %s", data.Id, extractedID)
	}
	log.Println("\n \n TestExtractIdFromEncryptedToken")

}

func TestExtractDetailsFromEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	token, err := service.CreateToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	claims, err := service.ExtractDetails(token, SecretKey, key)
	if err != nil {
		t.Errorf("Error extracting details from encrypted token: %v", err)
	}

	if claims == nil {
		t.Error("Failed to extract details from encrypted token")
	}
	log.Println("\n \n TestExtractDetailsFromEncryptedToken")

}

func TestExtractDetailsFromEncryptedTokenWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	type Test struct{
		Email string `json:"email" bson:"email"`
		Id string `json:"id" bson:"id"`
	}
	var data  Test
	data.Email = "guruakash.ec20@bitsathy.ac.in"
	data.Id = "123456"

	token, err := service.CreateTokenWithStruct(data, SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	claims, err := service.ExtractDetails(token, SecretKey, key)
	if err != nil {
		t.Errorf("Error extracting details from encrypted token: %v", err)
	}

	if claims == nil {
		t.Error("Failed to extract details from encrypted token")
	}
	log.Println("\n \n TestExtractDetailsFromEncryptedToken")

}

func TestValidateEncryptedtoken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	token, err := service.CreateToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	valid, err := service.IsTokenValid(token, SecretKey, key)
	if err != nil {
		t.Errorf("Error validating encrypted token: %v", err)
	}

	if !valid {
		t.Error("Encrypted token validation failed")
	}
	log.Println("\n \n TestValidateEncryptedtoken")

}

func TestTokenManager_BlockUnblockEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	token, err := service.CreateToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	tokenManager := service.NewTokenManager()


	err = tokenManager.BlockToken(token, key)
	if err != nil {
		t.Errorf("Error blocking encrypted token: %v", err)
	}

	blocked, err := tokenManager.IsTokenBlocked(token, key)
	if err != nil {
		t.Errorf("Error checking if encrypted token is blocked: %v", err)
	}
	log.Println("blocked", blocked)

	if !blocked {
		t.Error("Encrypted token should be blocked after blocking")
	}

	err = tokenManager.UnblockToken(token, SecretKey, key)
	if err != nil {
		t.Errorf("Error unblocking encrypted token: %v", err)
	}

	blocked, err = tokenManager.IsTokenBlocked(token, key)
	if err != nil {
		t.Errorf("Error checking if encrypted token is blocked: %v", err)
	}

	if blocked {
		t.Error("Encrypted token should not be blocked after unblocking")
	}

	log.Println("\n \n TestTokenManager_BlockUnblockEncryptedToken")

}

func TestGenerateAccessAndRefreshEncryptedTokens(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	accessToken, refreshToken, err := service.GenerateAccessAndRefreshTokens("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, key)
	if err != nil {
		t.Errorf("Error generating access and refresh tokens: %v", err)
	}

	if accessToken == "" || refreshToken == "" {
		t.Error("Access or refresh token generation failed")
	}
	log.Println("\n \n TestGenerateAccessAndRefreshEncryptedTokens")

}

func TestGenerateAccessAndRefreshEncryptedTokensWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	type Test struct{
		Email string `json:"email" bson:"email"`
		Id string `json:"id" bson:"id"`
	}
	var data  Test
	data.Email = "guruakash.ec20@bitsathy.ac.in"
	data.Id = "123456"

	accessToken, refreshToken, err := service.GenerateAccessAndRefreshEncryptedTokensWithStruct(data, SecretKey, key)
	if err != nil {
		t.Errorf("Error generating access and refresh tokens: %v", err)
	}

	if accessToken == "" || refreshToken == "" {
		t.Error("Access or refresh token generation failed")
	}
	log.Println("\n \n TestGenerateAccessAndRefreshEncryptedTokens")

}

func TestRefreshAccessEncryptedTokenWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	type Test struct{
		Email string `json:"email" bson:"email"`
		Id string `json:"id" bson:"id"`
	}
	var data  Test
	data.Email = "guruakash.ec20@bitsathy.ac.in"
	data.Id = "123456"

	refreshToken,_, err := service.GenerateAccessAndRefreshEncryptedTokensWithStruct(data, SecretKey, key)
	if err != nil {
		t.Errorf("Error creating refresh token: %v", err)
	}

	log.Println("Created Token")

	newAccessToken, err := service.RefreshAccessToken(refreshToken, SecretKey, key)
	if err != nil {
		t.Errorf("Error refreshing access token: %v", err)
	}

	if newAccessToken == "" {
		t.Error("New access token generation failed")
	}
	log.Println("\n \n TestRefreshAccessEncryptedToken")

}

func TestRefreshAccessEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	refreshToken,_, err := service.GenerateAccessAndRefreshTokens("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, key)
	if err != nil {
		t.Errorf("Error creating refresh token: %v", err)
	}

	log.Println("Created Token")

	newAccessToken, err := service.RefreshAccessToken(refreshToken, SecretKey, key)
	if err != nil {
		t.Errorf("Error refreshing access token: %v", err)
	}

	if newAccessToken == "" {
		t.Error("New access token generation failed")
	}
	log.Println("\n \n TestRefreshAccessEncryptedToken")

}


func TestExtractExpirationTimeFromEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	token, err := service.CreateToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	expirationTime, err := service.ExtractExpirationTime(token, key)
	if err != nil {
		t.Errorf("Error extracting expiration time from encrypted token: %v", err)
	}

	if expirationTime.IsZero() {
		t.Error("Expiration time extraction failed")
	}
	log.Println("\n \n TestExtractExpirationTimeFromEncryptedToken")

}

func TestEncryptAndDecryptToken(t *testing.T) {
	key := []byte("1234567890123456")
	SecretKey := "Anon@123456789"

	token, err := service.CreateToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	encryptedToken, err := encryptdecrypt.EncryptToken(token, key)
	if err != nil {
		t.Errorf("Error encrypting token: %v", err)
	}

	decryptedToken, err := encryptdecrypt.DecryptToken(encryptedToken, key)
	if err != nil {
		t.Errorf("Error decrypting token: %v", err)
	}

	if decryptedToken != token {
		t.Errorf("Expected decrypted token: %s, Got: %s", token, decryptedToken)
	}
	log.Println("\n \n TestEncryptAndDecryptToken")

}
