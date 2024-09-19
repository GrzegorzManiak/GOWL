package main

import (
	"GOWL/pkg"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

func main() {
	user := "Alice"
	pass := "deadbeef"
	serverName := "Server"

	//
	// -- Registration CLIENT -- //
	//
	curve := elliptic.P256()

	client := pkg.ClientInit(user, pass, serverName, curve)
	t, pi, T := client.Register()

	fmt.Println("t:", t.String())
	fmt.Println("pi:", pi.String())
	fmt.Println("T:", new(big.Int).SetBytes(T).String())

	//
	// -- Registration SERVER -- //
	//
	server := pkg.ServerInit(serverName, curve)
	X3, zkpX4 := server.RegisterUser()

	// Store: X3, zkpX4, user, pi, T

	fmt.Println("X3:", new(big.Int).SetBytes(X3).String())
	fmt.Println("V:", new(big.Int).SetBytes(zkpX4.V).String())
	fmt.Println("r:", new(big.Int).SetBytes(zkpX4.R.Bytes()).String())

}
