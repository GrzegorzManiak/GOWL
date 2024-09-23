import { RegisterOutput } from "./dto";
import { EncodeToBase64, GetCurve, GetG, Hash, ModuloN } from "./ops";
import { SupportedCurves } from "./types";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";

class Client {
    private userName: string;
    private password: string;
    private server: string;
    private curveKey: SupportedCurves;
    private curve: ReturnType<typeof GetCurve>;
    private G: ProjPointType<bigint>;

    public constructor(userName: string, password: string, server: string, curve: SupportedCurves) {
        this.userName = userName;
        this.password = password;
        this.server = server;
        this.curveKey = curve;
        this.curve = GetCurve(curve);
        this.G = GetG(curve);
    }

    public async Register(): Promise<RegisterOutput> {
        try {
            const t = ModuloN(await Hash(this.userName, this.password), this.curve.CURVE.n);
            const pi = ModuloN(await Hash(t), this.curve.CURVE.n);
            const T = this.G.multiply(t);
            return { User: this.userName, PI: EncodeToBase64(pi), T: EncodeToBase64(T.toRawBytes()) };
        }

        catch {
            throw new Error('Failed to register');
        }
    }
}

export {
    Client
};