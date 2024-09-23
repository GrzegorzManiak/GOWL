import { Client } from './client';
import { SupportedCurves } from './types';

export * from './types';
export * from './ops';
export * from './dto';
export * from './client';
export * from './schnorr';

const client = new Client('username', 'password', 'server', SupportedCurves.P256);
const out = await client.Register();

console.log(out);