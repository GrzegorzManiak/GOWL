import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { bytesToHex, bytesToNumberBE, concatBytes } from "@noble/curves/abstract/utils";
import { CurveMap, SupportedCurves } from "./types";

function GetCurve(curve: SupportedCurves) {
    const ChooseCurve = CurveMap[curve];
    if (!ChooseCurve) throw new Error('Invalid curve');
    return ChooseCurve;
}

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

function ModuloN(x: bigint, n: bigint) {
    return ((x % n) + n) % n;
}

async function HighEntropyRandom(from: bigint, to: bigint): Promise<bigint> {
    const range = to - from;
    const rangeBytes = BigIntToByteArray(range);
    let randomBigInt: bigint;

    do {
        const randomBytes = new Uint8Array(rangeBytes.length);
        crypto.getRandomValues(randomBytes);
        randomBigInt = bytesToNumberBE(randomBytes);
    } while (randomBigInt >= range);

    return from + randomBigInt;
}

async function GenerateKey(curve: SupportedCurves): Promise<bigint> {
    return await HighEntropyRandom(1n, GetCurve(curve).CURVE.n - 1n);
}

function IntTo4Bytes(i: number): Uint8Array {
    return new Uint8Array([i >> 24, i >> 16, i >> 8, i]);
}

function ToBytes(data: Uint8Array | bigint | string): Uint8Array {
    if (data instanceof Uint8Array) {
        const len = IntTo4Bytes(data.length);
        return concatBytes(len, data);
    } 

    else if (typeof data == 'bigint') {
        let bytes = BigIntToByteArray(data);
        const sign = bytes[0] >= 128 ? 0 : 1;
        bytes = new Uint8Array([sign, ...bytes]);
        const len = IntTo4Bytes(bytes.length);
        return concatBytes(len, bytes);
    } 

    else if (typeof data == 'string') {
        const bytes = new TextEncoder().encode(data);
        const len = IntTo4Bytes(data.length);
        return concatBytes(len, bytes);
    } 

    throw new Error('Invalid type passed to toBytes');
}

async function Hash(...args: Array<Uint8Array | bigint | string>): Promise<bigint> {
    const bytes = concatBytes(...args.map(ToBytes));
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return bytesToNumberBE(new Uint8Array(hash));
};

export {
    GetCurve,
    EncodeToBase64,
    ModuloN,
    HighEntropyRandom,
    GenerateKey,
    IntTo4Bytes,
    ToBytes,
    Hash
}