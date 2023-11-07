package dotEnv

import "testing"

func TestLoadDotEnv(t *testing.T) {
	err := LoadDotEnv()
	if err != nil {
		t.Errorf("Loading .env file FAILED: %v", err)
	} else {
		t.Logf("Loading .env file PASSED!")
	}
}
