package hashing

import (
	"crypto/rand"
	"log"

	"golang.org/x/crypto/bcrypt"
)

const saltSize = 16

func GenerateSalt() []byte {
	var salt = make([]byte, saltSize)

	_, err := rand.Read(salt[:])
	if err != nil {
		log.Fatal(err)
	}

	return salt
}

func HashPassword(password, salt []byte) []byte {
	password = append(password, salt...)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	return hashedPassword
}

func CheckHashedPassword(hashedPassword, password, salt []byte) bool {
	password = append(password, salt...)
	err := bcrypt.CompareHashAndPassword(hashedPassword, password)
	if err != nil {
		return false
	}
	return true
}
