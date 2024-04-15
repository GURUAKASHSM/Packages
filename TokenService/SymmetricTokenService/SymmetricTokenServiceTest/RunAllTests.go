package service_test

import (
	"testing"
)

func TestMain(m *testing.M) {
	RunAllTests()
}

func RunAllTests() {
	// Define a slice to hold all test functions
	tests := []testing.InternalTest{
		{Name: "TestCreateEncryptedToken", F: TestCreateEncryptedToken},
		{Name: "TestCreateEncryptedTokenWithStruct", F: TestCreateEncryptedTokenWithStruct},
		{Name: "TestExtractIdFromEncryptedToken", F: TestExtractIdFromEncryptedToken},
		{Name: "TestExtractDetailsFromEncryptedToken", F: TestExtractDetailsFromEncryptedToken},
		{Name: "TestValidateEncryptedtoken", F: TestValidateEncryptedtoken},
		{Name: "TestTokenManager_BlockUnblockEncryptedToken", F: TestTokenManager_BlockUnblockEncryptedToken},
		{Name: "TestGenerateAccessAndRefreshEncryptedTokens", F: TestGenerateAccessAndRefreshEncryptedTokens},
		{Name: "TestRefreshAccessEncryptedToken", F: TestRefreshAccessEncryptedToken},
		{Name: "TestExtractExpirationTimeFromEncryptedToken", F: TestExtractExpirationTimeFromEncryptedToken},
		{Name: "TestEncryptAndDecryptToken", F: TestEncryptAndDecryptToken},
		{Name: "TestCreateToken", F:TestCreateToken},
		{Name: "TestExtractIDFromToken", F:TestExtractIDFromToken},
		{Name: "TestExtractDetailsFromToken", F:TestExtractDetailsFromToken},
		{Name: "TestValidatetoken", F:TestValidatetoken},
		{Name: "TestTokenManager_BlockUnblockToken", F:TestTokenManager_BlockUnblockToken},
		{Name: "TestGenerateAccessAndRefreshTokens", F:TestGenerateAccessAndRefreshTokens},
		{Name: "TestRefreshAccessToken", F:TestRefreshAccessToken},
		{Name: "TestExtractExpirationTimeFromToken", F:TestExtractExpirationTimeFromToken},
		{Name: "TestExtractIdFromEncryptedTokenWithStruct", F: TestExtractIdFromEncryptedTokenWithStruct},
		{Name: "TestExtractDetailsFromEncryptedTokenWithStruct", F: TestExtractDetailsFromEncryptedTokenWithStruct},
		{Name: "TestGenerateAccessAndRefreshEncryptedTokensWithStruct", F: TestGenerateAccessAndRefreshEncryptedTokensWithStruct},
		{Name: "TestRefreshAccessEncryptedTokenWithStruct", F: TestRefreshAccessEncryptedTokenWithStruct},
		
		// Add other test functions here
	}

	// Run all the tests
	testing.Main(nil, tests, nil, nil)
}
