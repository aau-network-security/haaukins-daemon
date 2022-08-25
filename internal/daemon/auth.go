package daemon

import (
	"golang.org/x/crypto/bcrypt"
)

func verifyPassword(hash, password string) bool {
	byteHash := []byte(hash)
	bytePassword := []byte(password)

	if err := bcrypt.CompareHashAndPassword(byteHash, bytePassword); err != nil {
		return false
	}
	return true
}
