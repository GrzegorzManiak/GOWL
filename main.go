package main

import (
	"GOWL/pkg"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

func main() {
	curve := elliptic.P256()
	user := "Alice"
	pass := "deadbeef"
	serverName := "Server"

	if user == serverName {
		err := fmt.Errorf("User and Server cannot have the same name")
		panic(err)
	}

	//
	// -- Registration CLIENT -- //
	// Client Sends: user, t, π, T

	client := pkg.ClientInit(user, pass, serverName, curve)
	t, π, T := client.Register()

	fmt.Println("t:", t.String())
	fmt.Println("pi:", π.String())
	fmt.Println("T:", new(big.Int).SetBytes(T).String())

	//
	// -- Registration SERVER -- //
	// Store: X3, zkpX4, user, pi, T

	server := pkg.ServerInit(serverName, curve)
	X3, zkpX3 := server.RegisterUser()

	fmt.Println("X3:", new(big.Int).SetBytes(X3).String())
	fmt.Println("V:", new(big.Int).SetBytes(zkpX3.V).String())
	fmt.Println("r:", new(big.Int).SetBytes(zkpX3.R.Bytes()).String())

	//
	// -- Authentication Init CLIENT -- //
	// Client Sends: user, X1, X2, Π1, Π2
	X1, Π1, X2, Π2 := client.AuthInit()

	fmt.Println("X1:", new(big.Int).SetBytes(X1).String())
	fmt.Println("V1:", new(big.Int).SetBytes(Π1.V).String())

	fmt.Println("X2:", new(big.Int).SetBytes(X2).String())
	fmt.Println("V2:", new(big.Int).SetBytes(Π2.V).String())

	//
	// -- Authentication Init SERVER -- //
	// Server Sends: S, X3, X4, Π3, Π4, β, Πβ

	_, X4, β, Π3, Π4, Πβ := server.AuthInit(
		user,
		π,
		X1,
		X2,
		Π1,
		Π2,
	)

	//
	// -- Authentication Validate CLIENT -- //
	//

	α, Πα, r := client.AuthValidate(
		X3,
		X4,
		β,
		Π3,
		Π4,
		Πβ,
	)

	//
	// -- Authentication Validate SERVER -- //
	//
	server.AuthValidate(π, T, user, X1, X2, Π1, Π2, α, Πα, r)

	// OPT: Client verifies response from server
	client.VerifyResponse(X3, X4)
}
