package hashing

import "testing"

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil || len(salt) == 0 {
		t.Errorf("Salt generating FAILED: %v", err)
	} else {
		t.Logf("Salt generating PASSED!")
	}
}

func TestHashPassword(t *testing.T) {
	password := []byte("P@ssword123")
	salt := []byte{204, 147, 96, 31, 161, 121, 205, 53, 80, 41, 206, 98, 208, 29, 255, 174}
	hashedPassword, err := HashPassword(password, salt)
	if err != nil || len(hashedPassword) == 0 {
		t.Errorf("Password hashing FAILED: %v", err)
	} else {
		t.Logf("Password hashing PASSED!")
	}
}

func TestCheckHashedPassword(t *testing.T) {
	password := []byte("P@ssword123")
	salt := []byte{204, 147, 96, 31, 161, 121, 205, 53, 80, 41, 206, 98, 208, 29, 255, 174}
	hashedPassword := []byte{36, 50, 97, 36, 49, 48, 36, 109, 101, 79, 116, 71, 89, 103, 70, 103, 118, 113, 112, 120, 122, 111, 69, 53, 70, 80, 90, 90, 79, 112, 104, 81, 106, 114, 70, 109, 56, 80, 76, 100, 105, 90, 65, 117, 66, 118, 84, 86, 66, 56, 110, 103, 114, 79, 116, 70, 74, 49, 50, 113}
	res, err := CheckHashedPassword(hashedPassword, password, salt)
	if err != nil {
		t.Errorf("Hashed password checking FAILED: %v", err)
	} else if !res {
		t.Errorf("Hashed password checking FAILED: the hashed password is not hashed from the password!")
	} else {
		t.Logf("Hashed password checking PASSED!")
	}
}
