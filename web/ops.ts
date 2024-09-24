import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { bytesToHex, bytesToNumberBE, concatBytes } from "@noble/curves/abstract/utils";
import { CurveMap, SchnorrZKP, SupportedCurves } from "./types";

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

function BigIntFromBase64(base64: string): bigint {
    const bytes = new Uint8Array(atob(base64).split('').map(c => c.charCodeAt(0)));
    return bytesToNumberBE(bytes);
}

function PointFromBase64(curve: SupportedCurves, base64: string): ProjPointType<bigint> {
    const bytes = new Uint8Array(atob(base64).split('').map(c => c.charCodeAt(0)));
    return GetCurve(curve).ProjectivePoint.fromHex(bytesToHex(bytes));
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

function ToBytes(data: Uint8Array | bigint | string | SchnorrZKP): Uint8Array {
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

    else if (Object.keys(data).length === 2 && 'V' in data && 'r' in data) {
        const vBytes = data.V.toRawBytes();
        const rBytes = BigIntToByteArray(data.r);
        const vLen = IntTo4Bytes(vBytes.length);
        const rLen = IntTo4Bytes(rBytes.length);
        return concatBytes(vLen, vBytes, rLen, rBytes);
    }

    throw new Error('Invalid type passed to toBytes');
}

async function Hash(...args: Array<Uint8Array | bigint | string | SchnorrZKP>): Promise<bigint> {
    const bytes = concatBytes(...args.map(ToBytes));
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return bytesToNumberBE(new Uint8Array(hash));
};

function GetG(curve: SupportedCurves): ProjPointType<bigint> {
    const c = GetCurve(curve);
    return GetCurve(curve).ProjectivePoint.fromAffine({ x: c.CURVE.Gx, y: c.CURVE.Gy });
}

function CompareTo(a: bigint, b: bigint): number {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

function CalculateCofactor(curve: SupportedCurves): bigint {
    return GetCurve(curve).CURVE.h;
}

async function HMac(
    key: bigint,
    messageString: string,
    senderID: string,
    receiverID: string,
    senderKey1: Uint8Array,
    senderKey2: Uint8Array,
    receiverKey1: Uint8Array,
    receiverKey2: Uint8Array
): Promise<bigint> {
    const keyBytes = BigIntToByteArray(key);
    const mac = await crypto.subtle.importKey('raw', keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ['sign']);
    
    const data = [
        new TextEncoder().encode(messageString),
        new TextEncoder().encode(senderID),
        new TextEncoder().encode(receiverID),
        senderKey1,
        senderKey2,
        receiverKey1,
        receiverKey2
    ]

    const signature = await crypto.subtle.sign('HMAC', mac, concatBytes(...data));
    return BytesToBigInt(new Uint8Array(signature));
}

function BytesToBigInt(bytes: Uint8Array): bigint {
    let hex = Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
    return BigInt('0x' + hex);
}


export {
    BigIntFromBase64,
    BigIntToByteArray,
    GetCurve,
    EncodeToBase64,
    PointFromBase64,
    ModuloN,
    HighEntropyRandom,
    GenerateKey,
    IntTo4Bytes,
    ToBytes,
    GetG,
    Hash,
    CompareTo,
    HMac,
    BytesToBigInt,
    CalculateCofactor
}