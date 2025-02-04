package main

import (
	"fmt"
	"net/http"

	"github.com/omkero/GoJwtAuth/auth"
)

var secrete_key string = "256_bit_secret_key"

func NormalHandler(res http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(res, "This is a normal endpoint!")
}

func protectedHandler(res http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(res, "This is a protected endpoint!")
}

func main() {
	// init
	auth := auth.JwtSignToken{}

	// create token
	token, err := auth.CreateToken(secrete_key, 60*24, "hello sub")
	if err != nil {
		fmt.Println(err)
	}

	// verify if signature is valid
	isValid, err := auth.VerifyJwtSignature(token, []byte(secrete_key))
	if err != nil {
		fmt.Println(err)
	}

	// print output
	fmt.Println(isValid)
	fmt.Println(token)

	// Register the protected handler with the middleware using http.Handle
	http.Handle("/protected", auth.VerifyWithMiddleware(secrete_key, http.HandlerFunc(protectedHandler)))
	http.HandleFunc("/normal", NormalHandler)

	// start the server
	fmt.Println("Server is listening on port :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}
