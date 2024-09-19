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

	//client := pkg.ClientInit(user, pass, serverName, curve)
	//t, pi, T := client.Register()
	//
	//fmt.Println("t:", t.String())
	//fmt.Println("pi:", pi.String())
	//fmt.Println("T:", new(big.Int).SetBytes(T).String())
	//
	////
	//// -- Registration SERVER -- //
	//// Store: X3, zkpX4, user, pi, T
	//
	//server := pkg.ServerInit(serverName, curve)
	//X3, zkpX3 := server.RegisterUser()
	//
	//fmt.Println("X3:", new(big.Int).SetBytes(X3).String())
	//fmt.Println("V:", new(big.Int).SetBytes(zkpX3.V).String())
	//fmt.Println("r:", new(big.Int).SetBytes(zkpX3.R.Bytes()).String())
	//
	////
	//// -- Authentication Init CLIENT -- //
	//// Client Sends: user, X1, X2, Π1, Π2
	//X1, Π1, X2, Π2 := client.AuthInit()
	//
	//fmt.Println("X1:", new(big.Int).SetBytes(X1).String())
	//fmt.Println("V1:", new(big.Int).SetBytes(Π1.V).String())
	//
	//fmt.Println("X2:", new(big.Int).SetBytes(X2).String())
	//fmt.Println("V2:", new(big.Int).SetBytes(Π2.V).String())

	//
	// -- Authentication Init SERVER -- //
	// Server Sends: S, X3, X4, Π3, Π4, β, Πβ

	println("Server Init" + serverName + user + pass)
	X1, _ := new(big.Int).SetString("296107629349885433529313631978455887171453494963961034169444779943099421254587", 10)
	X2, _ := new(big.Int).SetString("396373871576663816936084317214382817670515908401866818960144220790588401533596", 10)
	X3, _ := new(big.Int).SetString("459374516632748979093048243439226263273564655061304308458850468200546173629166", 10)
	PI, _ := new(big.Int).SetString("100576120785382412396175613629765631892883317383397924468689937592634486189794", 10)
	X1V, _ := new(big.Int).SetString("347211264461001669060719334300419657631661703194827760071259508343578485550104", 10)
	X1R, _ := new(big.Int).SetString("78205306549196034358177139198310231393765674613136213855903569231449045215792", 10)
	X2V, _ := new(big.Int).SetString("404419687225746599287310115730292915380961474836335802778422232438146132753442", 10)
	X2R, _ := new(big.Int).SetString("90041963211003678040106327784849254706365538791203529258815714410010233634409", 10)

	Π1 := &pkg.SchnorrZKP{V: X1V.Bytes(), R: X1R}
	Π2 := &pkg.SchnorrZKP{V: X2V.Bytes(), R: X2R}

	server := pkg.Server{
		ServerName:  serverName,
		Curve:       curve,
		CurveParams: curve.Params(),
		X3:          X3.Bytes(),
	}

	server.AuthInit(
		user,
		PI,
		X1.Bytes(),
		X2.Bytes(),
		Π1,
		Π2,
	)

}
