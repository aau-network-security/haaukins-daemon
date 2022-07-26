package daemon

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// todo Need to create different tokens based on it is an admin login or participant login
func (d *daemon) createAdminToken(user database.AdminUser) (string, error) {
	atClaims := jwt.MapClaims{}
	atClaims["username"] = user.Username
	atClaims["role"] = user.RoleID
	atClaims["organization"] = user.OrganizationID
	atClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	atClaims["email"] = user.Email
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(d.conf.JwtSecret))
	if err != nil {
		return "", err
	}
	return token, nil
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

func (d *daemon) jwtExtract(c *gin.Context) string {
	token := c.GetHeader("Authorization")
	log.Debug().Msgf("Using secret key: %s", d.conf.JwtSecret)
	return token
}

func (d *daemon) jwtVerify(c *gin.Context) (*jwt.Token, error) {
	tokenString := d.jwtExtract(c)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(d.conf.JwtSecret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (d *daemon) jwtValidate(c *gin.Context) (jwt.MapClaims, error) {
	token, err := d.jwtVerify(c)
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

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (d *daemon) adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := d.jwtValidate(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, APIResponse{Status: "Invalid JWT"})
			return
		}
		// Passing jwt claims to next handler function
		c.Set("username", claims["username"])
		c.Set("email", claims["email"])
		c.Set("organization", claims["organization"])
		c.Set("role", claims["role"])
		c.Next()
	}
}
