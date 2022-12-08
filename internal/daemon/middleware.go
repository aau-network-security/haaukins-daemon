package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const psyduck string = `
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣆⢀⣶⡶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⢸⠟⣠⣶⡷⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣀⠀⢀⣠⠴⠴⠶⠚⠿⠿⠾⠭⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⠴⢋⡽⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠢⣀⠀⠀⠀⠀⠀⠀
⠀⠀⢀⡔⠁⡰⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠚⠛⣖⠀⠀⠀⠀
⠀⢀⡏⠀⡼⢡⠚⡛⠒⣄⠀⠀⠀⠀⣠⠖⠛⠛⠲⡄⠐⢯⠁⠀⠀⠹⡧⠀⠀⠀
⠀⣸⠀⠀⡇⠘⠦⣭⡤⢟⡤⠤⣀⠀⠣⣀⡉⢁⣀⠟⠀⠀⢷⠀⠀⠀⠙⣗⠀⠀
⠁⢻⠀⠀⢷⢀⡔⠉⢻⡅⣀⣤⡈⠙⠒⠺⠯⡍⠁⠀⠀⠀⢸⡆⠀⠀⠀⠘⡶⠄
⠀⣈⣧⠴⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⠃⠀⠀⠀⠀⣸⡇⠀⠀⠀⠀⠸⣔
⣾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣧⣤⡤⠴⠖⠋⢹⠃⠀⠀⠀⠀⠀⣷
⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣻⠁⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⣼
⠙⠑⣤⣀⠀⠀⠀⠀⠀⢀⠀⠀⢄⣐⠴⠋⠀⠀⠀⠀⠀⠀⠘⢆⠀⠀⠀⠀⣰⠟
⠀⠀⠀⣑⡟⠛⠛⠛⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢴⡾⠋⠀
⠀⠀⠀⡾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡇⠀⠀
⠀⠀⣰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀
⠀⠀⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠃⠀⠃
`

// todo Need to create different tokens based on it is an admin login or participant login
func (d *daemon) createAdminToken(ctx context.Context, user db.AdminUser) (string, error) {
	atClaims := jwt.MapClaims{}
	atClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	atClaims["jti"] = uuid.New()
	atClaims["sub"] = user.Username
	atClaims["participant"] = false
	atClaims["email"] = user.Email
	atClaims["organization"] = user.Organization
	atClaims["role"] = user.Role

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

func (d *daemon) jwtVerify(c *gin.Context, tokenFromClient string) (*jwt.Token, error) {
	tokenString := tokenFromClient
	if c != nil {
		tokenString = d.jwtExtract(c)
	}
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

func (d *daemon) jwtValidate(c *gin.Context, tokenFromClient string) (jwt.MapClaims, error) {
	token, err := d.jwtVerify(c, tokenFromClient)
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

func (d *daemon) adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := d.jwtValidate(c, "")
		if err != nil || claims["participant"] == true {
			if claims["participant"] == true {
				d.auditLogger.Warn().
					Str("username", claims["sub"].(string)).
					Str("email", claims["email"].(string)).
					Msg("Participant is trying to abuse admin api")
				c.Data(http.StatusUnauthorized, "text/plain; charset=utf-8", []byte(psyduck))
				c.Abort()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, APIResponse{Status: "Invalid JWT"})
			return
		}
		// Passing jwt claims to next handler function in the gin context
		c.Set("jti", claims["jti"])
		c.Set("exp", claims["exp"])
		c.Set("sub", claims["sub"])
		c.Set("email", claims["email"])
		c.Set("organization", claims["organization"])
		c.Set("role", claims["role"])
		c.Next()
	}
}
