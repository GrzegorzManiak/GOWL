import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { CurveMap, SupportedCurves } from "./types";

function GetG(curve: SupportedCurves): ProjPointType<bigint> {
    const c = GetCurve(curve);
    return GetCurve(curve).ProjectivePoint.fromAffine({ x: c.CURVE.Gx, y: c.CURVE.Gy });
}

function CalculateCofactor(curve: SupportedCurves): bigint {
    return GetCurve(curve).CURVE.h;
}

function GetCurve(curve: SupportedCurves) {
    const ChooseCurve = CurveMap[curve];
    if (!ChooseCurve) throw new Error('Invalid curve');
    return ChooseCurve;
}

export {
    GetG,
    CalculateCofactor,
    GetCurve
}