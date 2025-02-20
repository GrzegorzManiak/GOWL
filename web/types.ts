import { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';
import { secp256k1 } from "@noble/curves/secp256k1";

enum SupportedCurves {
    P256 = 256,
    P384 = 384,
    P521 = 521,
    SECP256K1 = 256_1
} 

const CurveMap = {
    [SupportedCurves.P256]: p256,
    [SupportedCurves.P384]: p384,
    [SupportedCurves.P521]: p521,
    [SupportedCurves.SECP256K1]: secp256k1
}

type SchnorrZKP = {
    V: ProjPointType<bigint>;
    r: bigint;
}

enum Keys {
    Session = 'session_key',
    Confirmation = 'confirmation_key'
}

enum KeyTags {
    ClientKC = 'KC_1_U',
    ServerKC = 'KC_1_V'
}

export {
    p256,
    p384,
    p521,
    CurveMap,
    SupportedCurves,
    SchnorrZKP,
    Keys,
    KeyTags
}