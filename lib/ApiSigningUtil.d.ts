export declare function setLogLevel(loglevel: string);
export declare function getHMACSignature(message: string | Buffer, secret: string | Buffer);
export declare function verifyHMACSignature(signature: string, secret: string | Buffer, message: string | Buffer);
export declare function getRSASignature(message: string | Buffer, privateKey: string, passphrase: string);
export declare function verifyRSASignature(signature: string, publicKey: string, message: string | Buffer);

export declare function getPrivateKeyFromPem(pemFileName: string);
export declare function getPublicKeyFromCer(cerFileName: string);

export declare function getSignatureBaseString(baseProps: object);

export declare function getTokenFromSecret(realm: string, authPrefix: string, httpMethod: string, urlPath: string, appId: string, secret: string, formJson?: object, nonce?: string, timestamp?: number);
export declare function getTokenFromCertFileName(realm: string, authPrefix: string, httpMethod: string, urlPath: string, appId: string, formJson?: string, passphrase: string, certFileName: string, nonce?: string, timestamp?: number);
export declare function getTokenFromCertString(realm: string, authPrefix: string, httpMethod: string, urlPath: string, appId: string, formJson?: object, passphrase: string, certString: string, nonce?: string, timestamp?: number);
export declare function getToken(realm: string, authPrefix: string, httpMethod: string, urlPath: string, appId: string, secret?: string, formJson?: object, passphrase?: string, certFileName?: string, nonce?: string, timestamp?: number, certString?: string);
export declare function getSignatureToken(reqProps: object);

export declare function makeHttpRequest(urlPath: string, token: string, formData?: object, httpMethod: string, port: number);