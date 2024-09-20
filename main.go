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

	//X1: 291527873065038658029434543999156023191731888933086013964755314683727060351946
	//x2: 28048054698464670087075807131323991123069734699031281255718814425862565568869
	//X3: 369511340874487527656946899870330879670424695957576595718965753113471569366294
	//X4: 253094542097102092013375394334715092698134783684676122040908020676074471923444
	//Beta: 347477892697409185136801658101107854831973589843217351289802526561922872905961
	X3raw, _ := new(big.Int).SetString("369511340874487527656946899870330879670424695957576595718965753113471569366294", 10)
	X4raw, _ := new(big.Int).SetString("253094542097102092013375394334715092698134783684676122040908020676074471923444", 10)
	BetaRaw, _ := new(big.Int).SetString("347477892697409185136801658101107854831973589843217351289802526561922872905961", 10)

	X3 = X3raw.Bytes()
	X4 = X4raw.Bytes()
	β = BetaRaw.Bytes()

	//
	// -- Authentication Validate CLIENT -- //
	//

	client.AuthValidate(
		X3,
		X4,
		β,
		Π3,
		Π4,
		Πβ,
	)
}
