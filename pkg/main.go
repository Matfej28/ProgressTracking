package main

import (
	"fmt"

	"github.com/Matfej28/ProgressTracking/pkg/hashing"
)

func main() {
	password := "P@ssword123"
	salt := []byte{204, 147, 96, 31, 161, 121, 205, 53, 80, 41, 206, 98, 208, 29, 255, 174}
	hashedPassword, _ := hashing.HashPassword([]byte(password), salt)
	fmt.Println(hashedPassword)
}
