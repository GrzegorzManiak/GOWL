> ## Disclaimer
> I am not a cryptographer, I am a software engineer. This implementation is for educational purposes only. Do not use this implementation in production. If you want to use the OWL aPake protocol, please use the Java implementation provided by the authors of the protocol.

# GOWL

GOWL Is a OWL aPake implementation in Go. OWL aPake is an Augmented Password-Authenticated Key Exchange Scheme


## Dose it work?
Yes, it works. I have tested it with the Java implementation provided by the authors of the protocol. The implementation is not optimized and it is **assumed not secure**. It is for educational purposes only. It has tests against the Java implementation provided by the authors of the protocol.

## Why GO?
I wanted to learn Go and I thought that implementing the OWL aPake protocol would be a good way to learn Go.

## How to use it?

Each function returns a struct that contains a `payload`, this payload is the **Only Data** that should be sent to the other party.

```go
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
```

## Resources
- [Paper 2023/768](https://eprint.iacr.org/2023/768.pdf) - The paper that describes the OWL aPake protocol
- [Java ECC Implementation](https://github.com/haofeng66/OwlDemo) - The Java implementation of the OWL aPake protocol
- [Usefull slides about OWL & ZKP](https://docs.google.com/presentation/d/1CWwMzutshb_oX0qUhPR-sSa02EK-BKiYDXYKDYJ49YI/edit) - Slides provided by the authors of the OWL aPake protocol