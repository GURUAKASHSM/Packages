package service_test

import (
	"log"
	"testing"

	service "github.com/GURUAKASHSM/Packages/TokenService/SymmetricTokenService/NonEncryptedToken"
)

func TestCreateToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"
	validtime := int64(1)

	token, err := service.CreateToken(email, id, SecretKey, validtime)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	if token == "" {
		t.Error("Token creation failed")
	}
	log.Println("\n \n TestCreateToken")

}

func TestExtractIDFromToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"
	validtime := int64(1)

	token, err := service.CreateToken(email, id, SecretKey, validtime)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	extractedID, err := service.ExtractID(token, SecretKey)
	if err != nil {
		t.Errorf("Error extracting ID from token: %v", err)
	}

	if extractedID != id {
		t.Errorf("Expected ID: %s, Got: %s", id, extractedID)
	}
	log.Println("\n \n TestExtractIDFromToken")

}

func TestExtractDetailsFromToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"
	validtime := int64(1)

	token, err := service.CreateToken(email, id, SecretKey, validtime)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	claims, err := service.ExtractDetails(token, SecretKey)
	if err != nil {
		t.Errorf("Error extracting details from token: %v", err)
	}

	if claims == nil {
		t.Error("Failed to extract details from token")
	}
	log.Println("\n \n TestExtractDetailsFromToken")

}

func TestValidatetoken(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"
	validtime := int64(1)

	token, err := service.CreateToken(email, id, SecretKey, validtime)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	valid := service.IsTokenValid(token, SecretKey)
	if !valid {
		t.Error("Token validation failed")
	}
	log.Println("\n \n TestValidatetoken")

}

func TestTokenManager_BlockUnblockToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"
	validtime := int64(1)

	token, err := service.CreateToken(email, id, SecretKey, validtime)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	tokenManager := service.NewTokenManager()

	err = tokenManager.BlockToken(token, SecretKey)
	if err != nil {
		t.Errorf("Error blocking token: %v", err)
	}

	if !tokenManager.IsTokenBlocked(token) {
		t.Error("Token should be blocked after blocking")
	}

	err = tokenManager.UnblockToken(token)
	if err != nil {
		t.Errorf("Error unblocking token: %v", err)
	}

	if tokenManager.IsTokenBlocked(token) {
		t.Error("Token should not be blocked after unblocking")
	}
	log.Println("\n \n TestTokenManager_BlockUnblockToken")

}

func TestGenerateAccessAndRefreshTokens(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"

	accessToken, refreshToken, err := service.GenerateAccessAndRefreshTokens(email, id, SecretKey)
	if err != nil {
		t.Errorf("Error generating access and refresh tokens: %v", err)
	}

	if accessToken == "" || refreshToken == "" {
		t.Error("Access or refresh token generation failed")
	}
	log.Println("\n \n TestGenerateAccessAndRefreshTokens")

}

func TestRefreshAccessToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"

	refreshToken, err := service.CreateToken(email, id, SecretKey, 1)
	if err != nil {
		t.Errorf("Error creating refresh token: %v", err)
	}

	newAccessToken, err := service.RefreshAccessToken(refreshToken, SecretKey)
	if err != nil {
		t.Errorf("Error refreshing access token: %v", err)
	}

	if newAccessToken == "" {
		t.Error("New access token generation failed")
	}
	log.Println("\n \n TestRefreshAccessToken")

}

func TestExtractExpirationTimeFromToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"
	validtime := int64(1)

	token, err := service.CreateToken(email, id, SecretKey, validtime)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	expirationTime, err := service.ExtractExpirationTime(token)
	if err != nil {
		t.Errorf("Error extracting expiration time from token: %v", err)
	}

	if expirationTime.IsZero() {
		t.Error("Expiration time extraction failed")
	}
	log.Println("\n \n TestExtractExpirationTimeFromToken")

}

func TestCreateTokenWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	type Test struct {
		Email string `json:"email" bson:"email"`
		Id    string `json:"id" bson:"id"`
	}
	data := Test{
		Email: "guruakash.ec20@bitsathy.ac.in",
		Id:    "123456",
	}
	validtime := int64(1)

	token, err := service.CreateTokenWithStruct(data, SecretKey, validtime)
	if err != nil {
		t.Errorf("Error creating token with struct: %v", err)
	}

	if token == "" {
		t.Error("Token creation with struct failed")
	}
	log.Println("\n \n TestCreateTokenWithStruct")
}

func TestGenerateAccessAndRefreshTokensWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	type Test struct {
		Email string `json:"email" bson:"email"`
		Id    string `json:"id" bson:"id"`
	}
	data := Test{
		Email: "guruakash.ec20@bitsathy.ac.in",
		Id:    "123456",
	}

	accessToken, refreshToken, err := service.GenerateAccessAndRefreshTokensWithStruct(data, SecretKey)
	if err != nil {
		t.Errorf("Error generating access and refresh tokens with struct: %v", err)
	}

	if accessToken == "" || refreshToken == "" {
		t.Error("Access or refresh token generation with struct failed")
	}
	log.Println("\n \n TestGenerateAccessAndRefreshTokensWithStruct")
}

func TestExtractIDWithStructFeild(t *testing.T) {
	SecretKey := "Anon@123456789"
	type Test struct {
		Email string `json:"email" bson:"email"`
		Id    string `json:"id" bson:"id"`
	}
	data := Test{
		Email: "guruakash.ec20@bitsathy.ac.in",
		Id:    "123456",
	}
	validtime := int64(1)

	token, err := service.CreateTokenWithStruct(data, SecretKey, validtime)
	if err != nil {
		t.Errorf("Error creating token with struct for ExtractIDWithStructFeild: %v", err)
	}

	extractedID, err := service.ExtractIDWithStructFeild(token, SecretKey, "id")
	if err != nil {
		t.Errorf("Error extracting ID from token with struct field: %v", err)
	}

	if extractedID != data.Id {
		t.Errorf("Expected ID: %s, Got: %s", data.Id, extractedID)
	}
	log.Println("\n \n TestExtractIDWithStructFeild")
}

func TestRefreshAccessTokenWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	type Test struct {
		Email string `json:"email" bson:"email"`
		Id    string `json:"id" bson:"id"`
	}
	data := Test{
		Email: "guruakash.ec20@bitsathy.ac.in",
		Id:    "123456",
	}
	refreshToken, _, err := service.GenerateAccessAndRefreshTokensWithStruct(data, SecretKey)
	if err != nil {
		t.Errorf("Error generating refresh token for RefreshAccessToken: %v", err)
	}

	newAccessToken, err := service.RefreshAccessToken(refreshToken, SecretKey)
	if err != nil {
		t.Errorf("Error refreshing access token: %v", err)
	}

	if newAccessToken == "" {
		t.Error("New access token generation failed")
	}
	log.Println("\n \n TestRefreshAccessToken")
}

func TestExtractIDFromTokenWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	type Test struct{
		Email string `json:"email" bson:"email"`
		Id string `json:"id" bson:"id"`
	}
	var data  Test
	data.Email = "guruakash.ec20@bitsathy.ac.in"
	data.Id = "123456"

	token, err := service.CreateTokenWithStruct(data, SecretKey, 1)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	extractedID, err := service.ExtractIDWithStructFeild(token, SecretKey, "id")
	if err != nil {
		t.Errorf("Error extracting ID from token: %v", err)
	}

	if extractedID != data.Id {
		t.Errorf("Expected ID: %s, Got: %s", data.Id, extractedID)
	}
	log.Println("\n \n TestExtractIDFromTokenWithStruct")
}

func TestExtractDetailsFromTokenWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	type Test struct{
		Email string `json:"email" bson:"email"`
		Id string `json:"id" bson:"id"`
	}
	var data  Test
	data.Email = "guruakash.ec20@bitsathy.ac.in"
	data.Id = "123456"

	token, err := service.CreateTokenWithStruct(data, SecretKey, 1)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	claims, err := service.ExtractDetails(token, SecretKey)
	if err != nil {
		t.Errorf("Error extracting details from token: %v", err)
	}

	if claims == nil {
		t.Error("Failed to extract details from token")
	}
	log.Println("\n \n TestExtractDetailsFromTokenWithStruct")
}

func TestExtractExpirationTimeFromTokenWithStruct(t *testing.T) {
	SecretKey := "Anon@123456789"
	type Test struct{
		Email string `json:"email" bson:"email"`
		Id string `json:"id" bson:"id"`
	}
	var data  Test
	data.Email = "guruakash.ec20@bitsathy.ac.in"
	data.Id = "123456"

	token, err := service.CreateTokenWithStruct(data, SecretKey, 1)
	if err != nil {
		t.Errorf("Error creating token: %v", err)
	}

	expirationTime, err := service.ExtractExpirationTime(token)
	if err != nil {
		t.Errorf("Error extracting expiration time from token: %v", err)
	}

	if expirationTime.IsZero() {
		t.Error("Expiration time extraction failed")
	}
	log.Println("\n \n TestExtractExpirationTimeFromTokenWithStruct")
}

