package main

import (
	"crypto/elliptic"
	"fmt"
	"github.com/GrzegorzManiak/GOWL/pkg/owl"
)

func main() {
	curve := elliptic.P256()
	user := "Alice"
	pass := "deadbeef"
	serverName := "Server"

	// -- Register
	client, err := owl.ClientInit(user, pass, serverName, curve)
	if err != nil {
		fmt.Println(err)
		return
	}

	clientRegistration := client.Register()

	server, err := owl.ServerInit(serverName, curve, clientRegistration.Payload)
	if err != nil {
		fmt.Println(err)
		return
	}

	serverRegistration := server.RegisterUser()

	// -- Auth Init
	clientInit := client.AuthInit()
	serverInit, err := server.AuthInit(serverRegistration, clientInit.Payload)
	if err != nil {
		fmt.Println(err)
		return
	}

	// -- Auth Validate
	clientValidate, err := client.AuthValidate(clientInit, serverInit.Payload)
	if err != nil {
		fmt.Println(err)
		return
	}

	serverValidate, err := server.AuthValidate(clientInit.Payload, clientValidate.Payload, serverInit)
	if err != nil {
		fmt.Println(err)
		return
	}

	println("Client Session Key:", clientValidate.ClientSessionKey.String())
	println("Server Session Key:", serverValidate.ServerSessionKey.String())

	// -- Verify Response (Optional)
	err = client.VerifyResponse(
		clientInit,
		clientValidate,
		serverInit.Payload,
		serverValidate.Payload,
	)

	if err != nil {
		fmt.Println(err)
		return
	}
}

//func main() {
//	curve := elliptic.P256()
//	user := "Alice"
//	pass := "deadbeef"
//	serverName := "Server"
//
//	//
//	// -- Registration CLIENT -- //
//	// Client Sends: user, t, π, T
//
//	client := pkgTEMP.ClientInit(user, pass, serverName, curve)
//	_, π, T := client.Register()
//
//	//
//	// -- Registration SERVER -- //
//	// Store: X3, zkpX4, user, pi, T
//
//	server := pkgTEMP.ServerInit(serverName, curve)
//	X3, _ := server.RegisterUser()
//
//	//
//	// -- Authentication Init CLIENT -- //
//	// Client Sends: user, X1, X2, Π1, Π2
//	X1, Π1, X2, Π2 := client.AuthInit()
//
//	//
//	// -- Authentication Init SERVER -- //
//	// Server Sends: S, X3, X4, Π3, Π4, β, Πβ
//
//	_, X4, β, Π3, Π4, Πβ := server.AuthInit(
//		user,
//		π,
//		X1,
//		X2,
//		Π1,
//		Π2,
//	)
//
//	//
//	// -- Authentication Validate CLIENT -- //
//	//
//
//	clientKCTag, α, Πα, r, ClientSessionKey := client.AuthValidate(
//		X3,
//		X4,
//		β,
//		Π3,
//		Π4,
//		Πβ,
//	)
//
//	//
//	// -- Authentication Validate SERVER -- //
//	//
//	serverKCTag, serverSessionKey := server.AuthValidate(clientKCTag, π, T, user, X1, X2, Π1, Π2, α, Πα, r)
//
//	// OPT: Client verifies response from server
//	client.VerifyResponse(serverKCTag, X3, X4)
//
//	fmt.Println("Client Session Key:", ClientSessionKey.String())
//	fmt.Println("Server Session Key:", serverSessionKey.String())
//}
