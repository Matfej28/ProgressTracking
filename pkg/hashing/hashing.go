package hashing

import (
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

const saltSize = 16

func GenerateSalt() ([]byte, error) {
	var salt = make([]byte, saltSize)

	_, err := rand.Read(salt[:])
	if err != nil {
		return []byte{}, err
	}
	return salt, err
}

func HashPassword(password, salt []byte) ([]byte, error) {
	password = append(password, salt...)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return []byte{}, err
	}

	return hashedPassword, err
}

func CheckHashedPassword(hashedPassword, password, salt []byte) (bool, error) {
	password = append(password, salt...)
	err := bcrypt.CompareHashAndPassword(hashedPassword, password)
	if err != nil {
		return false, err
	}
	return true, nil
}
