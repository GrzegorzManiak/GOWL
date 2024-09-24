import { bytesToNumberBE, concatBytes } from '@noble/curves/abstract/utils';
import { ToBytes } from './ops';
import { SchnorrZKP } from './types';

async function Hash(...args: Array<Uint8Array | bigint | string | SchnorrZKP>): Promise<bigint> {
    const bytes = concatBytes(...args.map(ToBytes));
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    return bytesToNumberBE(new Uint8Array(hash));
}

export {
    Hash
}