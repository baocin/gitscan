// Package fixtures contains intentionally vulnerable code for testing.
// DO NOT use these values in production - they are fake test credentials.
package fixtures

// FAKE_SECRET_FOR_TESTING - This is an intentionally planted fake secret
// for integration testing of the gitscan security scanner.
// These are NOT real credentials and exist solely to verify that the
// scanner correctly detects hardcoded secrets.

// FakeAWSCredentials - obviously fake AWS keys for testing secret detection
const (
	// This looks like an AWS access key but is fake (starts with AKIA but invalid)
	FakeAWSAccessKey = "AKIAIOSFODNN7EXAMPLE"
	// This looks like an AWS secret key but is fake
	FakeAWSSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// FakeGitHubToken - fake GitHub personal access token for testing
// Real GitHub tokens start with ghp_, gho_, ghu_, ghs_, or ghr_
const FakeGitHubToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

// FakeAPIKey - generic fake API key pattern
const FakeAPIKey = "api_key_test_1234567890abcdef"

// FakePassword - hardcoded password for testing detection
const FakePassword = "password123_this_is_fake"

// FakeConfig demonstrates hardcoded credentials in config
var FakeConfig = map[string]string{
	"database_password": "super_secret_db_pass_FAKE",
	"api_secret":        "sk_test_FAKE1234567890",
	"jwt_secret":        "my-super-secret-jwt-key-for-testing",
}

// FakePrivateKey - fake RSA private key header for testing
const FakePrivateKey = `-----BEGIN RSA PRIVATE KEY-----
FAKE_KEY_FOR_TESTING_ONLY_NOT_REAL
This is intentionally malformed and not a real key.
It exists to test that the scanner detects private key patterns.
-----END RSA PRIVATE KEY-----`

// GetFakeCredentials returns fake credentials for testing purposes only
func GetFakeCredentials() map[string]string {
	return map[string]string{
		"aws_access_key": FakeAWSAccessKey,
		"aws_secret_key": FakeAWSSecretKey,
		"github_token":   FakeGitHubToken,
		"password":       FakePassword,
	}
}
