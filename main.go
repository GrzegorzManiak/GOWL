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

	// -- Registration
	curve := elliptic.P256()
	curveParams := curve.Params()

	n := curveParams.N
	g := elliptic.MarshalCompressed(curve, curveParams.Gx, curveParams.Gy)

	t := pkg.ModuloN(pkg.Hash(user, pass), n)
	pi := pkg.ModuloN(pkg.Hash(t), n)

	// Perform scalar multiplication G * t
	tx, ty := curve.ScalarMult(curveParams.Gx, curveParams.Gy, t.Bytes())
	T := elliptic.MarshalCompressed(curve, tx, ty)

	// Print the resulting point T
	fmt.Printf("T_x: %s\n", tx.String())
	fmt.Printf("T_y: %s\n", ty.String())

	fmt.Println("t:", t.String())
	fmt.Println("pi:", pi.String())
	fmt.Println("T:", new(big.Int).SetBytes(T).String())
	fmt.Println("G:", new(big.Int).SetBytes(g).String())

}
