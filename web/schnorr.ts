import { CalculateCofactor, GetCurve } from "./ecc_ops";
import { Hash } from "./hash";
import { CompareTo, GenerateKey, ModuloN } from "./ops";
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

async function VerifyZKP(
    curve: SupportedCurves,
    generator: ProjPointType<bigint>,
    X: ProjPointType<bigint>,
    zkp: SchnorrZKP,
    prover: string
): Promise<boolean> {

    const h = await Hash(generator.toRawBytes(), zkp.V.toRawBytes(), X.toRawBytes(), prover);
    if (!X || !zkp.V || !zkp.r) return false;

    try { X.assertValidity(); } 
    catch { return false; }

    const { x: xX, y: yY } = X.toAffine();
    if (xX === null || yY === null) return false;

    const curveParams = GetCurve(curve);
    if (CompareTo(xX, BigInt(0)) === -1 || CompareTo(xX, curveParams.CURVE.n - BigInt(1)) === 1) return false;
    if (CompareTo(yY, BigInt(0)) === -1 || CompareTo(yY, curveParams.CURVE.n - BigInt(1)) === 1) return false;

    const xXh = X.multiply(CalculateCofactor(curve));
    const { x: xXhX, y: xXhY } = xXh.toAffine();
    if (xXhX === null || xXhY === null) return false;
    if (xXhX === BigInt(0) && xXhY === BigInt(0)) return false;

    const gRxhmn = generator.multiply(zkp.r).add(X.multiply(ModuloN(h, curveParams.CURVE.n)));
    return zkp.V.equals(gRxhmn);
}

export {
    GenerateZKPGProvided,
    VerifyZKP
}