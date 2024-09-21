package main

import (
	"GOWL/pkgTEMP"
	"crypto/elliptic"
	"fmt"
)

func main() {
	curve := elliptic.P256()
	user := "Alice"
	pass := "deadbeef"
	serverName := "Server"

	//
	// -- Registration CLIENT -- //
	// Client Sends: user, t, π, T

	client := pkgTEMP.ClientInit(user, pass, serverName, curve)
	_, π, T := client.Register()

	//
	// -- Registration SERVER -- //
	// Store: X3, zkpX4, user, pi, T

	server := pkgTEMP.ServerInit(serverName, curve)
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
