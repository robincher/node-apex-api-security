export declare function setLogLevel(loglevel: string);
export declare function getL1Signature(message: string | Buffer, secret: string | Buffer);
export declare function verifyL1Signature(signature: string, secret: string | Buffer, message: string | Buffer);
export declare function getL2Signature(message: string | Buffer, privateKey: string, passphrase: string);
export declare function verifyL2Signature(signature: string, publicKey: string, message: string | Buffer);

export declare function getPrivateKeyFromPem(pemFileName: string);
export declare function getPublicKeyFromCer(cerFileName: string);

export declare function getBaseString(authPrefix: string, signatureMethod: string, appId: string, urlPath: string, httpMethod: string, formData?: object, nonce: string, timestamp: number);

export declare function getTokenFromSecret(realm: string, authPrefix: string, httpMethod: string, urlPath: string, appId: string, secret: string, formJson?: object, nonce?: string, timestamp?: number);
export declare function getTokenFromCertFileName(realm: string, authPrefix: string, httpMethod: string, urlPath: string, appId: string, formJson?: string, passphrase: string, certFileName: string, nonce?: string, timestamp?: number);
export declare function getTokenFromCertString(realm: string, authPrefix: string, httpMethod: string, urlPath: string, appId: string, formJson?: object, passphrase: string, certString: string, nonce?: string, timestamp?: number);

export declare function makeHttpRequest(urlPath: string, token: string, formData?: object, httpMethod: string, port: number);