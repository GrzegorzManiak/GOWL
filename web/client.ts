import { ClientAuthInit, RegisterOutput, ServerAuthInit } from "./dto";
import { BigIntFromBase64, EncodeToBase64, GenerateKey, GetCurve, GetG, Hash, ModuloN, PointFromBase64 } from "./ops";
import { GenerateZKPGProvided, VerifyZKP } from "./schnorr";
import { SchnorrZKP, SupportedCurves } from "./types";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";

class Client {
    private userName: string;
    private password: string;
    private server: string;
    private curveKey: SupportedCurves;
    private curve: ReturnType<typeof GetCurve>;
    private G: ProjPointType<bigint>;
    private N: bigint;

    private hasInit: boolean = false;
    private pi: bigint = 0n;
    private t: bigint = 0n;
    private x1: bigint = 0n;
    private x2: bigint = 0n;
    private X1: ProjPointType<bigint> | undefined;
    private X2: ProjPointType<bigint> | undefined;
    private PI1: SchnorrZKP | undefined;
    private PI2: SchnorrZKP | undefined;
    

    public constructor(userName: string, password: string, server: string, curve: SupportedCurves) {
        this.userName = userName;
        this.password = password;
        this.server = server;
        this.curveKey = curve;
        this.curve = GetCurve(curve);
        this.G = GetG(curve);
        this.N = this.curve.CURVE.n;
    }

    public async Register(): Promise<RegisterOutput> {
        try {
            const t = ModuloN(await Hash(this.userName, this.password), this.curve.CURVE.n);
            const T = this.G.multiply(t);
            this.pi = ModuloN(await Hash(t), this.curve.CURVE.n);
            return { User: this.userName, PI: EncodeToBase64(this.pi), T: EncodeToBase64(T.toRawBytes()) };
        }

        catch {
            throw new Error('Failed to register');
        }
    }

    public async AuthInit(): Promise<ClientAuthInit> {
        try {
            this.t = ModuloN(await Hash(this.userName, this.password), this.curve.CURVE.n);
            this.pi = ModuloN(await Hash(this.t), this.curve.CURVE.n);

            this.x1 = await GenerateKey(this.curveKey);
            this.X1 = this.G.multiply(this.x1);
            this.PI1 = await GenerateZKPGProvided(this.curveKey, this.G, this.N, this.x1, this.X1, this.userName);

            this.x2 = await  GenerateKey(this.curveKey);
            this.X2 = this.G.multiply(this.x2);
            this.PI2 = await GenerateZKPGProvided(this.curveKey, this.G, this.N, this.x2, this.X2, this.userName);

            this.hasInit = true;

            return { 
                User: this.userName, 
                X1: EncodeToBase64(this.X1.toRawBytes()), X2: EncodeToBase64(this.X2.toRawBytes()), 
                PI1_V: EncodeToBase64(this.PI1.V.toRawBytes()), PI2_V: EncodeToBase64(this.PI2.V.toRawBytes()),
                PI1_R: EncodeToBase64(this.PI1.r), PI2_R: EncodeToBase64(this.PI2.r) 
            };
        }

        catch {
            throw new Error('Failed to authenticate (Init)');
        }
    }

    public async AuthVerify(serverInit: ServerAuthInit): Promise<void> {
        if (!this.hasInit) throw new Error('AuthInit must be called before AuthVerify');
        if (!this.X1 || !this.X2 || !this.PI1 || !this.PI2) throw new Error('AuthInit must be called before AuthVerify');

        try {
            const [ X3, X4, PI3, PI4, Beta, PIBeta] = [
                PointFromBase64(this.curveKey, serverInit.X3), 
                PointFromBase64(this.curveKey, serverInit.X4),
                { V: PointFromBase64(this.curveKey, serverInit.PI3_V), r: BigIntFromBase64(serverInit.PI3_R) },
                { V: PointFromBase64(this.curveKey, serverInit.PI4_V), r: BigIntFromBase64(serverInit.PI4_R) },
                PointFromBase64(this.curveKey, serverInit.Beta),
                { V: PointFromBase64(this.curveKey, serverInit.PIBeta_V), r: BigIntFromBase64(serverInit.PIBeta_R) }
            ];
            
            
            if (! await VerifyZKP(this.curveKey, this.G, X3, PI3, this.server)) throw new Error('Failed to authenticate PI3 (Verify)');
            if (! await VerifyZKP(this.curveKey, this.G, X4, PI4, this.server)) throw new Error('Failed to authenticate PI4 (Verify)');
            const GBeta = this.X1.add(this.X2).add(X3);
            if (! await VerifyZKP(this.curveKey, GBeta, Beta, PIBeta, this.server)) throw new Error('Failed to authenticate PIBeta (Verify)');

            console.log('PI3 verified');
        }

        catch (e) {
            console.error(e);
            throw new Error('Failed to authenticate (Verify)');
        }
    }
}

export {
    Client
};