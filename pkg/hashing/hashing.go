package hashing

import (
	"crypto/rand"
	"log"

	"golang.org/x/crypto/bcrypt"
)

const saltSize = 16

func GenerateSalt() string {
	var salt = make([]byte, saltSize)

	_, err := rand.Read(salt[:])
	if err != nil {
		log.Fatal(err)
	}

	return string(salt)
}

func HashPassword(password, salt string) string {
	password = password + salt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hashedPassword)
}
