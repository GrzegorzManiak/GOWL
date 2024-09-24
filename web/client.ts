import { ClientAuthInit, ClientAuthInitPrivate, ClientAuthVerify, ClientAuthVerifyPrivate, RegisterOutput, ServerAuthInit, ServerAuthVerify } from './dto';
import { GetCurve, GetG } from './ecc_ops';
import { Hash } from './hash';
import { HMac } from './hmac';
import { BigIntFromBase64, EncodeToBase64, PointFromBase64 } from './marshaler';
import { CompareTo, GenerateKey, ModuloN } from './ops';
import { GenerateZKPGProvided, VerifyZKP } from './schnorr';
import { Keys, KeyTags, SupportedCurves } from './types';
import { ProjPointType } from '@noble/curves/abstract/weierstrass';

class Client {
    private userName: string;
    private password: string;
    private server: string;
    private curveKey: SupportedCurves;
    private curve: ReturnType<typeof GetCurve>;
    private G: ProjPointType<bigint>;
    private N: bigint;

    private clientAuthInit: ClientAuthInitPrivate | undefined;
    private clientAuthVerify: ClientAuthVerifyPrivate | undefined;
    private clientKCKey: bigint | undefined;
    private clientSessionKey: bigint | undefined;
    
    public constructor(userName: string, password: string, server: string, curve: SupportedCurves) {
        this.userName = userName;
        this.password = password;
        this.server = server;
        this.curveKey = curve;
        this.curve = GetCurve(curve);
        this.G = GetG(curve);
        this.N = this.curve.CURVE.n;
    }

    public async Register(): Promise<RegisterOutput | Error> {
        try {
            const t = ModuloN(await Hash(this.userName, this.password), this.curve.CURVE.n);
            const T = this.G.multiply(t);
            const PI = ModuloN(await Hash(t), this.curve.CURVE.n);
            return { User: this.userName, PI: EncodeToBase64(PI), T: EncodeToBase64(T.toRawBytes()) };
        }

        catch (e) {
            console.error(e);
            return new Error('Failed to register user');
        }
    }

    public async AuthInit(): Promise<ClientAuthInit | Error> {
        try {
            const t = ModuloN(await Hash(this.userName, this.password), this.curve.CURVE.n);
            const T = this.G.multiply(t);
            const PI = ModuloN(await Hash(t), this.curve.CURVE.n);

            const x1 = await GenerateKey(this.curveKey);
            const X1 = this.G.multiply(x1);
            const PI1 = await GenerateZKPGProvided(this.curveKey, this.G, this.N, x1, X1, this.userName);

            const x2 = await  GenerateKey(this.curveKey);
            const X2 = this.G.multiply(x2);
            const PI2 = await GenerateZKPGProvided(this.curveKey, this.G, this.N, x2, X2, this.userName);
            
            this.clientAuthInit = { PI: PI, t: t, T: T, x1: x1, x2: x2, X1: X1, X2: X2, PI1: PI1, PI2: PI2 };

            return { 
                User: this.userName, 
                X1: EncodeToBase64(X1.toRawBytes()), X2: EncodeToBase64(X2.toRawBytes()), 
                PI1_V: EncodeToBase64(PI1.V.toRawBytes()), PI2_V: EncodeToBase64(PI2.V.toRawBytes()),
                PI1_R: EncodeToBase64(PI1.r), PI2_R: EncodeToBase64(PI2.r) 
            };
        }

        catch (e) {
            console.error(e);
            return new Error('Failed to authenticate (AuthInit)');
        }
    }

    private ParseServerInit(serverInit: ServerAuthInit): ClientAuthVerifyPrivate | Error {
        try {
            const [ X3, X4, PI3, PI4, Beta, PIBeta] = [
                PointFromBase64(this.curveKey, serverInit.X3), 
                PointFromBase64(this.curveKey, serverInit.X4),
                { V: PointFromBase64(this.curveKey, serverInit.PI3_V), r: BigIntFromBase64(serverInit.PI3_R) },
                { V: PointFromBase64(this.curveKey, serverInit.PI4_V), r: BigIntFromBase64(serverInit.PI4_R) },
                PointFromBase64(this.curveKey, serverInit.Beta),
                { V: PointFromBase64(this.curveKey, serverInit.PIBeta_V), r: BigIntFromBase64(serverInit.PIBeta_R) }
            ];

            return { X3, X4, PI3, PI4, Beta, PIBeta };
        }

        catch (e) {
            console.error(e);
            return new Error('Failed to authenticate (ParseServerInit)');
        }
    }

    public async AuthVerify(serverInit: ServerAuthInit): Promise<ClientAuthVerify | Error> {
        const parsedRequest = this.ParseServerInit(serverInit);
        if (parsedRequest instanceof Error) return parsedRequest;
        this.clientAuthVerify = parsedRequest;

        try {
            if (!this.clientAuthInit) throw new Error('AuthInit must be called before AuthVerify');
            if (!this.clientAuthVerify) throw new Error('Failed to authenticate (Init)');

            const { X3, X4, PI3, PI4, Beta, PIBeta } = this.clientAuthVerify;
            const { x1, x2, X1, X2, PI1, PI2, t, PI } = this.clientAuthInit;

            if (! await VerifyZKP(this.curveKey, this.G, X3, PI3, this.server)) 
                throw new Error('Failed to authenticate PI3 (Verify)');

            if (! await VerifyZKP(this.curveKey, this.G, X4, PI4, this.server)) 
                throw new Error('Failed to authenticate PI4 (Verify)');

            const GBeta = X1.add(X2).add(X3);
            if (! await VerifyZKP(this.curveKey, GBeta, Beta, PIBeta, this.server)) 
                throw new Error('Failed to authenticate PIBeta (Verify)');

            const GAlpha = X1.add(X3).add(X4);
            const x2pi = ModuloN(x2 * PI, this.N);
            const Alpha = GAlpha.multiply(x2pi);
            const PIAlpha = await GenerateZKPGProvided(this.curveKey, GAlpha, this.N, x2pi, Alpha, this.userName);

            let rawClientKey = Beta.subtract(X4.multiply(x2pi));
            rawClientKey = rawClientKey.multiply(x2);

            this.clientSessionKey = await Hash(rawClientKey.toRawBytes(), Keys.Session);
            this.clientKCKey = await Hash(rawClientKey.toRawBytes(), Keys.Confirmation);

            const hTranscript = await Hash(
                rawClientKey.toRawBytes(),
                this.userName,
                X1.toRawBytes(), X2.toRawBytes(),
                PI1, PI2,
                this.server,
                X3.toRawBytes(), X4.toRawBytes(),
                PI3, PI4,
                Beta.toRawBytes(), PIBeta,
                Alpha.toRawBytes(), PIAlpha
            );

            const rValue = ModuloN(x1 - (t * hTranscript), this.N)

            const clientKCTag = await HMac(
                this.clientKCKey, 
                KeyTags.ClientKC,
                this.userName,
                this.server,
                X1.toRawBytes(),
                X2.toRawBytes(),
                X3.toRawBytes(),
                X4.toRawBytes()
            );

            return {
                Alpha: EncodeToBase64(Alpha.toRawBytes()),
                PIAlpha_V: EncodeToBase64(PIAlpha.V.toRawBytes()),
                PIAlpha_R: EncodeToBase64(PIAlpha.r),
                R: EncodeToBase64(rValue),
                ClientKCTag: EncodeToBase64(clientKCTag)
            };
        }

        catch (e) {
            console.error(e);
            return Error('Failed to authenticate (Verify)');
        }
    }

    public async ValidateServer(serverVerify: ServerAuthVerify): Promise<void | Error> {
        try {
            if (!this.clientKCKey) throw new Error('AuthVerify must be called before ValidateServer');
            if (!this.clientAuthInit) throw new Error('AuthVerify must be called before ValidateServer');
            if (!this.clientAuthVerify) throw new Error('AuthVerify must be called before ValidateServer');

            const { X3, X4 } = this.clientAuthVerify;
            const { X1, X2 } = this.clientAuthInit;

            const serverKcTag2 = await HMac(
                this.clientKCKey,
                KeyTags.ServerKC,
                this.server,
                this.userName,
                X3.toRawBytes(),
                X4.toRawBytes(),
                X1.toRawBytes(),
                X2.toRawBytes()
            );

            const serverKCTagc = BigIntFromBase64(serverVerify.ServerKCTag);
            if (CompareTo(serverKcTag2, serverKCTagc) !== 0) throw new Error('Failed to validate server (KCTag)');
        }

        catch (e) {
            console.error(e);
            return new Error('Failed to validate server (KCTag)');
        }
    }

    public GetSessionKey(): bigint | Error {
        if (!this.clientSessionKey) return new Error('Session key not generated');
        return this.clientSessionKey;
    }
}

export {
    Client
}