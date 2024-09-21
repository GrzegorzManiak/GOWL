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
