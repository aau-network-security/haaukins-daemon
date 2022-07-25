package daemon

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// todo Need to create different tokens based on it is an admin login or participant login
func createAdminToken() (string, error) {
	// var err error
	// atClaims := jwt.MapClaims{}
	// atClaims["authorized"] = true
	// atClaims["username"] = user.Username
	// atClaims["role"] = user.Role
	// atClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	// atClaims["email"] = user.Email
	// at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	// token, err := at.SignedString([]byte(SECRET_KEY))
	// if err != nil {
	// 	return "", err
	// }
	// return token, nil
	return "token", nil
}

func createParticipantToken() (string, error) {
	// var err error
	// atClaims := jwt.MapClaims{}
	// atClaims["authorized"] = true
	// atClaims["username"] = user.Username
	// atClaims["role"] = user.Role
	// atClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	// atClaims["email"] = user.Email
	// at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	// token, err := at.SignedString([]byte(SECRET_KEY))
	// if err != nil {
	// 	return "", err
	// }
	// return token, nil
	return "token", nil
}

func jwtExtract(c *gin.Context) string {
	token := c.GetHeader("Authorization")
	var SECRET_KEY = os.Getenv("SECRET_KEY")
	log.Debug().Msgf("Using secret key: ", SECRET_KEY)
	return token
}

func jwtVerify(c *gin.Context) (*jwt.Token, error) {
	tokenString := jwtExtract(c)
	var SECRET_KEY = os.Getenv("SECRET_KEY")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(SECRET_KEY), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func jwtValidate(c *gin.Context) (jwt.MapClaims, error) {
	token, err := jwtVerify(c)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		log.Printf("Invalid JWT Token")
		return nil, errors.New("token invalid")
	}
}

func tokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		//enableCors(&w)
		/*if r.Method == "OPTIONS" {
			return
		}*/
		_, err := jwtValidate(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, APIResponse{Status: "Invalid JWT"})
			return
		}
	}
}
