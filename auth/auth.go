package auth

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtSignToken struct {
	SecreteKey []byte
	Duration   time.Time
}

func (j *JwtSignToken) CreateToken(secreteKey string, expireDuration int, clamisWord string) (string, error) {

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": clamisWord,                                                         // you cann add anything you want in the clamis
		"exp": time.Now().Add(time.Minute * time.Duration(expireDuration)).Unix(), // expire date by minutes
		"iat": time.Now().Unix(),                                                  // issued at
	})

	tokenString, err := jwtToken.SignedString([]byte(secreteKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JwtSignToken) VerifyJwtSignature(tokenString string, secreteKey []byte) (bool, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return secreteKey, nil
	})

	if err != nil {
		return false, err
	}

	if !token.Valid {
		return false, err
	}
	return true, nil
}

func (j *JwtSignToken) DecodeJwtToken(tokenString string, secreteKey []byte) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return secreteKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, nil
	}

	return token, nil
}

func (j *JwtSignToken) VerifyWithMiddleware(secreteKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("x_api_key")
		if apiKey != secreteKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}
