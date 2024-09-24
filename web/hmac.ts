import { BigIntToByteArray } from './marshaler';
import { BytesToBigInt } from './ops';
import { concatBytes } from '@noble/curves/abstract/utils';

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
    const mac = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    
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

export {
    HMac
}