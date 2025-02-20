import { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { bytesToHex, bytesToNumberBE } from '@noble/curves/abstract/utils';
import { SupportedCurves } from './types';
import { GetCurve } from './ecc_ops';

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
    return UrlSafeBase64Encode(bytes);
}

function BigIntFromBase64(base64: string): bigint {
    return bytesToNumberBE(UrlSafeBase64Decode(base64));
}

function PointFromBase64(curve: SupportedCurves, base64: string): ProjPointType<bigint> {
    return GetCurve(curve).ProjectivePoint.fromHex(bytesToHex(UrlSafeBase64Decode(base64)));
}

function UrlSafeBase64Encode(data: Uint8Array | bigint): string {
    if (typeof data === 'bigint') data = BigIntToByteArray(data);
    const base64 = Buffer.from(data).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function UrlSafeBase64Decode(data: string): Uint8Array {
    return new Uint8Array(Buffer.from(data.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}

export {
    BigIntToByteArray,
    EncodeToBase64,
    BigIntFromBase64,
    PointFromBase64,

    UrlSafeBase64Encode,
    UrlSafeBase64Decode
}