package main

import (
	"GOWL/pkg"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

func main() {

	curve := elliptic.P256()
	x4, _ := new(big.Int).SetString("92924331714289309598568614385937331082154360548563534854722084561713080926489", 10)
	X1, _ := new(big.Int).SetString("288438714641929240027029931372999143558714506934172228766293993205802594260844", 10)
	X2, _ := new(big.Int).SetString("453734318552357647078608644220761958869868470888134244220420421725657807268071", 10)
	X3, _ := new(big.Int).SetString("246086805365699144396089482588823946208867075564847145794408353263640742077663", 10)
	PI, _ := new(big.Int).SetString("100576120785382412396175613629765631892883317383397924468689937592634486189794", 10)

	X1Bytes := X1.Bytes()
	X2Bytes := X2.Bytes()
	X3Bytes := X3.Bytes()

	Gβ := pkg.Add(curve, pkg.Add(curve, X1Bytes, X2Bytes), X3Bytes)
	x4Pi := pkg.ModuloN(pkg.Multiply(x4, PI), curve.Params().N)
	β := pkg.MultiplyX(curve, &Gβ, x4Pi)

	// -- Print out GBeta, x4Pi, and Beta
	fmt.Println("Gβ:", new(big.Int).SetBytes(Gβ).String())
	fmt.Println("x4Pi:", x4Pi.String())
	fmt.Println("β:", new(big.Int).SetBytes(β).String())

	g := pkg.GetG(curve)
	zkpBeta := pkg.GenerateZKPGProvided(
		curve,
		&Gβ,
		curve.Params().N,
		x4Pi,
		β,
		"Server",
	)

	isValid := pkg.VerifyZKP(curve, *g, β, *zkpBeta, "Server")
	fmt.Println("Is Valid:", isValid)
}

func main2() {
	curve := elliptic.P256()
	user := "Alice"
	pass := "deadbeef"
	serverName := "Server"

	//
	// -- Registration CLIENT -- //
	// Client Sends: user, t, π, T

	client := pkg.ClientInit(user, pass, serverName, curve)
	_, π, T := client.Register()

	//
	// -- Registration SERVER -- //
	// Store: X3, zkpX4, user, pi, T

	server := pkg.ServerInit(serverName, curve)
	X3, _ := server.RegisterUser()

	//
	// -- Authentication Init CLIENT -- //
	// Client Sends: user, X1, X2, Π1, Π2
	X1, Π1, X2, Π2 := client.AuthInit()

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

	clientKCTag, α, Πα, r, ClientSessionKey := client.AuthValidate(
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
	serverKCTag, serverSessionKey := server.AuthValidate(clientKCTag, π, T, user, X1, X2, Π1, Π2, α, Πα, r)

	// OPT: Client verifies response from server
	client.VerifyResponse(serverKCTag, X3, X4)

	fmt.Println("Client Session Key:", ClientSessionKey.String())
	fmt.Println("Server Session Key:", serverSessionKey.String())
}
