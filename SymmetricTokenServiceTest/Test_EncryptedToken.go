package service_test

import (
	"log"
	"testing"

	service "github.com/GURUAKASHSM/Packages/SymmetricTokenService"
)

func TestCreateEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	email := "guruakash.ec20@bitsathy.ac.in"
	id := "123456"
	validtime := int64(1)
	key := []byte("1234567890123456")

	encryptedToken, err := service.CreateEncryptedToken(email, id, SecretKey, validtime, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	if encryptedToken == "" {
		t.Error("Encrypted token creation failed")
	}
	log.Println("\n \n ")
}

func TestExtractIdFromEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	id := "123456"
	key := []byte("1234567890123456")

	token, err := service.CreateEncryptedToken("guruakash.ec20@bitsathy.ac.in", id, SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	extractedID, err := service.ExtractIdFromEncryptedToken(token, SecretKey, key)
	if err != nil {
		t.Errorf("Error extracting ID from encrypted token: %v", err)
	}

	if extractedID != id {
		t.Errorf("Expected ID: %s, Got: %s", id, extractedID)
	}
	log.Println("\n \n ")

}

func TestExtractDetailsFromEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	token, err := service.CreateEncryptedToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	claims, err := service.ExtractDetailsFromEncryptedToken(token, SecretKey, key)
	if err != nil {
		t.Errorf("Error extracting details from encrypted token: %v", err)
	}

	if claims == nil {
		t.Error("Failed to extract details from encrypted token")
	}
	log.Println("\n \n ")

}

func TestValidateEncryptedtoken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	token, err := service.CreateEncryptedToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	valid, err := service.ValidateEncryptedtoken(token, SecretKey, key)
	if err != nil {
		t.Errorf("Error validating encrypted token: %v", err)
	}

	if !valid {
		t.Error("Encrypted token validation failed")
	}
	log.Println("\n \n ")

}

func TestTokenManager_BlockUnblockEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	token, err := service.CreateEncryptedToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	tokenManager := service.NewTokenManager()

	err = tokenManager.BlockEncryptedToken(token, key)
	if err != nil {
		t.Errorf("Error blocking encrypted token: %v", err)
	}

	blocked, err := tokenManager.IsEncryptedTokenBlocked(token, key)
	if err != nil {
		t.Errorf("Error checking if encrypted token is blocked: %v", err)
	}
	log.Println("blocked", blocked)

	if !blocked {
		t.Error("Encrypted token should be blocked after blocking")
	}

	err = tokenManager.UnblockEncryptedToken(token, SecretKey, key)
	if err != nil {
		t.Errorf("Error unblocking encrypted token: %v", err)
	}

	blocked, err = tokenManager.IsEncryptedTokenBlocked(token, key)
	if err != nil {
		t.Errorf("Error checking if encrypted token is blocked: %v", err)
	}

	if blocked {
		t.Error("Encrypted token should not be blocked after unblocking")
	}

	log.Println("\n \n ")

}

func TestGenerateAccessAndRefreshEncryptedTokens(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	accessToken, refreshToken, err := service.GenerateAccessAndRefreshEncryptedTokens("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, key)
	if err != nil {
		t.Errorf("Error generating access and refresh tokens: %v", err)
	}

	if accessToken == "" || refreshToken == "" {
		t.Error("Access or refresh token generation failed")
	}
	log.Println("\n \n ")

}

func TestRefreshAccessEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	refreshToken, err := service.CreateEncryptedToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating refresh token: %v", err)
	}

	newAccessToken, err := service.RefreshAccessEncryptedToken(refreshToken, SecretKey, key)
	if err != nil {
		t.Errorf("Error refreshing access token: %v", err)
	}

	if newAccessToken == "" {
		t.Error("New access token generation failed")
	}
	log.Println("\n \n ")

}

func TestExtractExpirationTimeFromEncryptedToken(t *testing.T) {
	SecretKey := "Anon@123456789"
	key := []byte("1234567890123456")

	token, err := service.CreateEncryptedToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	expirationTime, err := service.ExtractExpirationTimeFromEncryptedToken(token, key)
	if err != nil {
		t.Errorf("Error extracting expiration time from encrypted token: %v", err)
	}

	if expirationTime.IsZero() {
		t.Error("Expiration time extraction failed")
	}
	log.Println("\n \n ")

}

func TestEncryptAndDecryptToken(t *testing.T) {
	key := []byte("1234567890123456")
	SecretKey := "Anon@123456789"

	token, err := service.CreateEncryptedToken("guruakash.ec20@bitsathy.ac.in", "123456", SecretKey, 1, key)
	if err != nil {
		t.Errorf("Error creating encrypted token: %v", err)
	}

	encryptedToken, err := service.EncryptToken(token, key)
	if err != nil {
		t.Errorf("Error encrypting token: %v", err)
	}

	decryptedToken, err := service.DecryptToken(encryptedToken, key)
	if err != nil {
		t.Errorf("Error decrypting token: %v", err)
	}

	if decryptedToken != token {
		t.Errorf("Expected decrypted token: %s, Got: %s", token, decryptedToken)
	}
	log.Println("\n \n ")

}
