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

	//
	// -- Registration CLIENT -- //
	// Client Sends: user, t, π, T

	client := pkg.ClientInit(user, pass, serverName, curve)
	t, pi, T := client.Register()

	fmt.Println("t:", t.String())
	fmt.Println("pi:", pi.String())
	fmt.Println("T:", new(big.Int).SetBytes(T).String())

	//
	// -- Registration SERVER -- //
	// Store: X3, zkpX4, user, pi, T

	server := pkg.ServerInit(serverName, curve)
	X3, zkpX4 := server.RegisterUser()

	fmt.Println("X3:", new(big.Int).SetBytes(X3).String())
	fmt.Println("V:", new(big.Int).SetBytes(zkpX4.V).String())
	fmt.Println("r:", new(big.Int).SetBytes(zkpX4.R.Bytes()).String())

	//
	// -- Authentication Init CLIENT -- //
	// Client Sends: user, X1, X2, Π1, Π2

	x1, Π1, x2, Π2 := client.AuthInit()

	fmt.Println("x1:", x1.String())
	fmt.Println("V1:", new(big.Int).SetBytes(Π1.V).String())

	fmt.Println("x2:", x2.String())
	fmt.Println("V2:", new(big.Int).SetBytes(Π2.V).String())

	//
	// -- Authentication Init SERVER -- //
	// Server Sends: S, X3, X4, Π3, Π4, β, Πβ

}
