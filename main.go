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
	curveParams := curve.Params()

	t := pkg.ModuloN(pkg.Hash(user, pass), curveParams.N)
	pi := pkg.ModuloN(pkg.Hash(t), curveParams.N)
	T := pkg.MultiplyG(curve, t)

	fmt.Println("t:", t.String())
	fmt.Println("pi:", pi.String())
	fmt.Println("T:", new(big.Int).SetBytes(T).String())

	//
	// -- Registration SERVER -- //
	//
	x3 := pkg.Generatex3(curveParams.N)
	X3 := pkg.MultiplyG(curve, x3)
	zkpX4 := pkg.GenerateZKP(curve, curveParams.N, x3, X3, serverName)

	fmt.Println("x3:", x3.String())
	fmt.Println("X3:", new(big.Int).SetBytes(X3).String())
	fmt.Println("V:", new(big.Int).SetBytes(zkpX4.V).String())
	fmt.Println("r:", new(big.Int).SetBytes(zkpX4.R.Bytes()).String())

}
