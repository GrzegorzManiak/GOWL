import { bytesToNumberBE, concatBytes } from '@noble/curves/abstract/utils';
import { SchnorrZKP, SupportedCurves } from './types';
import { BigIntToByteArray } from './marshaler';
import { GetCurve } from './ecc_ops';

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

function CompareTo(a: bigint, b: bigint): number {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

function BytesToBigInt(bytes: Uint8Array): bigint {
    let hex = Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
    return BigInt('0x' + hex);
}


export {
    ModuloN,
    HighEntropyRandom,
    GenerateKey,
    IntTo4Bytes,
    ToBytes,
    CompareTo,
    BytesToBigInt,
}