import { GenerateKey, Hash, ModuloN } from "./ops";
import { SchnorrZKP, SupportedCurves } from "./types";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";

async function GenerateZKPGProvided(
    curve: SupportedCurves, 
    g: ProjPointType<bigint>, 
    n: bigint, 
    x: bigint, 
    X: ProjPointType<bigint>, 
    prover: string
): Promise<SchnorrZKP> {
    const v = await GenerateKey(curve)
    const V = g.multiply(v);
    const h = await Hash(g.toRawBytes(), V.toRawBytes(), X.toRawBytes(), prover);
    let r = x * h;
    r = v - r;
    r = ModuloN(r, n);
    return { V, r };
};

// func VerifyZKP(
// 	curve elliptic.Curve,
// 	generator []byte,
// 	X []byte,
// 	zkp SchnorrZKP,
// 	prover string,
// ) bool {
// 	h := Hash(generator, zkp.V, X, prover)

// 	if X == nil || zkp.V == nil || zkp.R == nil {
// 		return false
// 	}

// 	xX, xY := elliptic.UnmarshalCompressed(curve, X)
// 	if IsInfinity(xX, xY) {
// 		return false
// 	}

// 	if xX.Cmp(big.NewInt(0)) == -1 || xX.Cmp(new(big.Int).Sub(curve.Params().N, big.NewInt(1))) == 1 {
// 		return false
// 	}

// 	if xY.Cmp(big.NewInt(0)) == -1 || xY.Cmp(new(big.Int).Sub(curve.Params().N, big.NewInt(1))) == 1 {
// 		return false
// 	}

// 	if !curve.IsOnCurve(xX, xY) {
// 		return false
// 	}

// 	xXh := MultiplyPoint(curve, &X, CalculateCofactor(curve))
// 	xXhX, xXhY := elliptic.UnmarshalCompressed(curve, xXh)
// 	if IsInfinity(xXhX, xXhY) {
// 		return false
// 	}

// 	gRxhmn := AddPoints(curve, MultiplyPoint(curve, &generator, zkp.R), MultiplyPoint(curve, &X, ModuloN(h, curve.Params().N)))
// 	return PointsEqual(curve, zkp.V, gRxhmn)
// }

export {
    GenerateZKPGProvided
}