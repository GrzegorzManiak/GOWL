import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { bytesToHex, bytesToNumberBE } from "@noble/curves/abstract/utils";
import { SupportedCurves } from "./types";
import { GetCurve } from "./ecc_ops";

function BigIntToByteArray(int: BigInt): Uint8Array {
    let hexString = int.toString(16);
    if (hexString.length % 2) hexString = '0' + hexString;
    const byteArray = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < byteArray.length; i++) byteArray[i] = parseInt(hexString.substr(i * 2, 2), 16);
    return byteArray;
}

function EncodeToBase64(data: Uint8Array | BigInt): string {
    let bytes;
    if (data instanceof BigInt || typeof data == 'bigint') bytes = BigIntToByteArray(data);
    else if (data instanceof Uint8Array) bytes = data;
    else throw new Error('Invalid type passed to encodeToBase64');
    return btoa(String.fromCharCode(...bytes));
}

function BigIntFromBase64(base64: string): bigint {
    const bytes = new Uint8Array(atob(base64).split('').map(c => c.charCodeAt(0)));
    return bytesToNumberBE(bytes);
}

function PointFromBase64(curve: SupportedCurves, base64: string): ProjPointType<bigint> {
    const bytes = new Uint8Array(atob(base64).split('').map(c => c.charCodeAt(0)));
    return GetCurve(curve).ProjectivePoint.fromHex(bytesToHex(bytes));
}

export {
    BigIntToByteArray,
    EncodeToBase64,
    BigIntFromBase64,
    PointFromBase64
}