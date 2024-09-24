type RegisterOutput = {
    User: string;
    PI: string;
    T: string;
}

type ClientAuthInit = {
    User: string;
    X1: string;
    X2: string;
    PI1_V: string;
    PI2_V: string;
    PI1_R: string;
    PI2_R: string;
}

type ServerAuthInit = {
    X3: string;
    X4: string;
    PI3_V: string;
    PI4_V: string;
    PI3_R: string;
    PI4_R: string;
    Beta: string;
    PIBeta_V: string;
    PIBeta_R: string;
}

type ClientAuthVerify = {
    ClientKCTag: string;
    Alpha: string;
    PIAlpha_V: string;
    PIAlpha_R: string;
    R: string;
}

type ServerAuthVerify = {
    ServerKCTag: string;
}

export {
    RegisterOutput,
    ClientAuthInit,
    ServerAuthInit,
    ClientAuthVerify,
    ServerAuthVerify
}