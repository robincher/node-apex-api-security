export declare function getHMACSignature(message: string , secret: string);

export declare function verifyHMACSignature(signature: string, secret: string, message: string);

export declare function getRSASignature(message: string, privateKey: string, passphrase: string);

export declare function verifyRSASignature(signature: string, publicKey: string, message: string);

export declare function getPrivateKeyFromPem(pemFileName: string);

export declare function getPublicKeyFromCer(cerFileName: string);

export declare function getSignatureBaseString(baseProps: object);

export declare function getSignatureToken(reqProps: object);
