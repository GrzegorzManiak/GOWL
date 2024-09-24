import { Client } from './client';
import { SupportedCurves } from './types';

export * from './types';
export * from './ops';
export * from './dto';
export * from './client';
export * from './schnorr';

const server = 'http://localhost:8080';
const registerURL = `${server}/register`;
const loginInitURL = `${server}/login/init`;
const loginVerifyURL = `${server}/login/verify`;


//
// -- Register
//

let client = new Client('username', 'password', 'server', SupportedCurves.P256);
const register = await client.Register();

const sendRegistrationRequest = await fetch(registerURL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...register, TOS: true })
});

if (!sendRegistrationRequest.ok) {
    const text = await sendRegistrationRequest.text();
    console.error(text);
    throw new Error('Failed to register');
}



//
// -- Login (Init)
//

client = new Client('username', 'password', 'server', SupportedCurves.P256);
const authInit = await client.AuthInit();

const sendAuthInitRequest = await fetch(loginInitURL, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(authInit)
});

if (!sendAuthInitRequest.ok) {
    const text = await sendAuthInitRequest.text();
    console.error(text);
    throw new Error('Failed to authenticate (Init)');
}

const authInitResponse = await sendAuthInitRequest.json();

//
// -- Login (Verify)
//

const authVerify = await client.AuthVerify(authInitResponse);
console.log(authVerify)
const sendAuthVerifyRequest = await fetch(loginVerifyURL, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(authVerify)
});

if (!sendAuthVerifyRequest.ok) {
    const text = await sendAuthVerifyRequest.text();
    console.error(text);
    throw new Error('Failed to authenticate (Verify)');
}
