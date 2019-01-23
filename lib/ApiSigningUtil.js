const _ = require('lodash');
const qs = require('querystring');
const crypto = require('crypto');
const fs = require('fs');
const {URL} = require('url');
const winston = require('./Logger');

let ApiSigningUtil = {};

function isNullOrEmpty(data) {
    return !data;
}

/**
 * Set winston logging mechanism
 *
 * @param {string} loglevel Logging level (trace,error,none)
 * @public
 */
ApiSigningUtil.setLogLevel = (loglevel) => {
    winston.level = loglevel;
};

ApiSigningUtil.getDefaultParam = (baseProps) => {
    let defaultParams = {};

    let prefixedAppId = baseProps.authPrefix.toLowerCase() + '_app_id';
    let prefixedNonce = baseProps.authPrefix.toLowerCase() + '_nonce';
    let prefixedSignatureMethod = baseProps.authPrefix.toLowerCase() + '_signature_method';
    let prefixedTimestamp = baseProps.authPrefix.toLowerCase() + '_timestamp';
    let prefixedVersion = baseProps.authPrefix.toLowerCase() + '_version';

    if (baseProps.signatureMethod === undefined || baseProps.signatureMethod === '') {
        if (baseProps.secret === undefined || baseProps.secret === '') {
            baseProps.signatureMethod = 'SHA256withRSA';
        } else {
            baseProps.signatureMethod = 'HMACSHA256';
        }
    }

    if (baseProps.timestamp === undefined || baseProps.timestamp === '') {
        baseProps.timestamp = (new Date).getTime();
    }

    if (baseProps.nonce === undefined || baseProps.nonce === '') {
        baseProps.nonce = crypto.randomBytes(32).toString('base64');
    }

    if (baseProps.version === undefined || baseProps.version === '') {
        baseProps.version = '1.0';
    }

    _.set(defaultParams, prefixedAppId, baseProps.appId);
    _.set(defaultParams, prefixedNonce, baseProps.nonce);
    _.set(defaultParams, prefixedSignatureMethod, baseProps.signatureMethod);
    _.set(defaultParams, prefixedTimestamp, baseProps.timestamp);
    _.set(defaultParams, prefixedVersion, baseProps.version);

    return defaultParams;
};

/**
 * Parse a JSON object by converting it to a 2 items array for further processing.
 * This is to remove queryString or formData with null value , empty string or duplicate key name
 * @param {object} json object to have its params sorted and parsed
 *
 * @returns {Array} 2-dimension Array that consits of the query or formData params
 * @private
 */
ApiSigningUtil.parseParams = (json) => {
    // As JSON doe not support property with sub-object as shown below
    // convert json from { "name" : { "name1" : "value1" } to { "name" : "" }
    let safeQueryStringJson = qs.parse(qs.stringify(json));

    let result = [];
    let keys = Object.keys(safeQueryStringJson);

    keys.forEach(function (key) {
        if (Array.isArray(safeQueryStringJson[key])) {
            // Convert array value to name=value,name=value
            safeQueryStringJson[key].forEach(function (value) {
                result.push([key, value]);
            });
        } else {
            result.push([key, safeQueryStringJson[key]]);
        }
    });
    return result;
};

/**
 * Create HMACRSA256 Signature (L1) with a given message
 *
 * @param {string} message Message to be signed
 * @param {string} secret App's secret
 *
 * @returns {string} signature HMACRSA256 Signature
 * @public
 */
ApiSigningUtil.getHMACSignature = (message, secret) => {
    winston.logEnter(message, secret);

    if (isNullOrEmpty(message) || isNullOrEmpty(secret)) {
        let compiled = _.template('<%= message %> and <%= secret %> must not be null or empty!');
        let errorMessage = compiled({
            'message': 'message',
            'secret': 'secret'
        });

        winston.error(errorMessage);
        throw new Error(errorMessage);
    }

    let signature = crypto.createHmac('SHA256', secret).update(message).digest('base64');

    winston.logExit(signature);
    return signature;
};

/**
 * Verify HMAC256 Signature (L1)
 *
 * @param {string} signature Signature to be verified
 * @param {string} secret App's secret
 * @param {string} message Message to be signed
 *
 * @returns {boolean} Verification status
 * @public
 */
ApiSigningUtil.verifyHMACSignature = (signature, secret, message) => {
    winston.logEnter(signature, secret, message);
    winston.logExit(_.isEqual(signature, ApiSigningUtil.getHMACSignature(message, secret)));
    return _.isEqual(signature, ApiSigningUtil.getHMACSignature(message, secret));
};

/**
 * Create RSA256 Signature (Lw) with a given message
 *
 * @param {string} message Message to be signed
 * @param {string} privateKey Private key
 * @param {string} passphrase Passphrase
 *
 * @returns {number} signature RSA256 Signature
 * @public
 */
ApiSigningUtil.getRSASignature = (message, privateKey, passphrase) => {
    winston.logEnter(message, 'privateKey***', 'passphrase***');

    if (isNullOrEmpty(message) || (privateKey == null)) {
        let compiled = _.template('<%= message %> and <%= privateKey %> must not be null or empty!');
        let errorMessage = compiled({
            'message': 'message',
            'privateKey': 'privateKey'
        });

        winston.error(errorMessage);
        throw new Error(errorMessage);
    }

    let signature = crypto.createSign('RSA-SHA256')
        .update(message)
        .sign({
            key: privateKey,
            passphrase: passphrase
        }, 'base64');

    winston.logExit(signature);
    return signature;
};


/**
 * Verify RSA256 Signature (L2)
 *
 * @param {string} signature Signature to be verified
 * @param {string} publicKey Public Key
 * @param {string} message Message to be signed
 *
 * @returns {boolean} Verification status
 * @public
 */
ApiSigningUtil.verifyRSASignature = (signature, publicKey, message) => {
    winston.logEnter(signature, 'publicKey***', message);

    if (isNullOrEmpty(message) || (publicKey == null)) {
        let compiled = _.template('<%= message %> and <%= publicKey %> must not be null or empty!');
        let errorMessage = compiled({
            'message': 'message',
            'publicKey': 'publicKey'
        });

        winston.error(errorMessage);
        throw new Error(errorMessage);
    }

    let verifier = crypto.createVerify('sha256');
    verifier.update(message);
    let verifyResult = verifier.verify(publicKey, signature, 'base64');

    winston.logExit(verifyResult);
    return verifyResult;
};

ApiSigningUtil.getPrivateKeyFromPem = (pemFileName) => {
    winston.logEnterExit(pemFileName);

    return fs.readFileSync(pemFileName, 'utf-8');
};

ApiSigningUtil.getPublicKeyFromCer = (cerFileName) => {
    winston.logEnterExit(cerFileName);

    return fs.readFileSync(cerFileName, 'utf-8');
};

/**
 * Generate HTTP Authorize Signature Header for API Gateway
 *
 * @param {object} reqProps HTTP Signature request properties
 * @param {string} reqProps.authPrefix Auth Prefix
 * @param {string} reqProps.appId Apex App ID
 * @param {string} reqProps.urlPath Endpoint URL
 * @param {string} reqProps.httpMethod HTTP Verb
 * @param {string} [reqProps.realm] An identifier for the caller, this can be set to any value.
 * @param {string} [reqProps.secret] Apex App Secret (for L1)
 * @param {string} [reqProps.keyFile] Path to key file for signing request (L2)
 * @param {string} [reqProps.keyString] String containing private key content in PEM format (L2)
 * @param {string} [reqProps.certFileName] (deprecated) Path to key file for signing request (L2)
 * @param {string} [reqProps.certString] (deprecated) String containing private key content in PEM format (L2)
 * @param {string} [reqProps.passphrase] Password, if any, for private key
 * @param {object} [reqProps.queryString] Additional query strings which would be flattened in key-value format
 * @param {object} [reqProps.formData] HTTP POST or PUT body in x-www-form-urlencoded format
 * @param {number} [reqProps.nonce] A nonce. Use once only
 * @param {number} [reqProps.timestamp] Unix timestamp (ms)
 *
 * @returns {string} signatureToken HTTP Signature token to be append in Authorization header in HTTP
 * @public
 */
ApiSigningUtil.getSignatureToken = (reqProps) => {
    winston.logEnter(JSON.stringify(reqProps));

    // Input validation since this is the public facing API
    if (!reqProps.authPrefix || !reqProps.appId || !reqProps.urlPath || !reqProps.httpMethod) {
        throw new Error('One or more required parameters are missing!');
    }

    // Throw error if no credentials are given
    if (reqProps.secret == null && reqProps.certFileName == null && reqProps.certString == null &&
        reqProps.keyFile == null && reqProps.keyString == null) {
        throw new Error('No secret or key specified for signing!');
    }

    let authPrefix = reqProps.authPrefix.toLowerCase();
    let signature = '';
    let realm = reqProps.realm || reqProps.appId;
    let signatureMethod = _.isNil(reqProps.secret) ? 'SHA256withRSA' : 'HMACSHA256';

    let baseProps = {
        authPrefix: authPrefix.toLowerCase(),
        signatureMethod: signatureMethod,
        appId: reqProps.appId,
        urlPath: reqProps.urlPath,
        httpMethod: reqProps.httpMethod,
        queryString: reqProps.queryString || null,
        formData: reqProps.formData || null,
        nonce: reqProps.nonce || crypto.randomBytes(32).toString('base64'),
        timestamp: reqProps.timestamp || (new Date).getTime()
    };

    let keyFile = reqProps.keyFile || reqProps.certFileName;
    let keyString = reqProps.keyString || reqProps.certString;

    let baseString = ApiSigningUtil.getSignatureBaseString(baseProps);

    if (!_.isNil(reqProps.secret)) {
        signature = ApiSigningUtil.getHMACSignature(baseString, reqProps.secret);
    } else {
        let privateKey = (keyFile ? ApiSigningUtil.getPrivateKeyFromPem(keyFile) : keyString);
        signature = ApiSigningUtil.getRSASignature(baseString, privateKey, reqProps.passphrase);
    }

    // reactor to use getDefaultParam()
    reqProps.timestamp = baseProps.timestamp;
    reqProps.nonce = baseProps.nonce;
    reqProps.signature = signature;

    baseProps.signature = signature;
    baseProps.realm = realm;

    let signatureToken = authPrefix.charAt(0).toUpperCase() + authPrefix.slice(1) + ' realm="' + reqProps.realm + '"';
    let defaultParams = ApiSigningUtil.getDefaultParam(baseProps);
    defaultParams[authPrefix + '_signature'] = baseProps.signature;

    let keys = Object.keys(defaultParams);
    keys.forEach(function (key) {
        signatureToken = signatureToken + ', ' + key + '="' + defaultParams[key] + '"';
    });

    winston.logExit(signatureToken);
    return signatureToken;
};

/**
 * Formulate Apex Signature base string
 *
 * @param {object} baseProps Base string formulation request properties in JSON object
 * @param {string} baseProps.authPrefix Apex auth prefix
 * @param {string} baseProps.signatureMethod If L1 auth, HMACSHA256; if L2 auth, SHA256withRSA
 * @param {string} baseProps.appId Apex app ID
 * @param {string} baseProps.httpMethod HTTP Verb
 * @param {number} [baseProps.nonce] A nonce. Use once only
 * @param {number} [baseProps.timestamp] Unix timestamp (ms)
 * @param {object} [baseProps.queryString] Query string in API
 * @param {object} [baseProps.formData] HTTP POST or PUT body in x-www-form-urlencoded format
 *
 * @returns {string} sigBaseString Signature base string for signing
 * @public
 */
ApiSigningUtil.getSignatureBaseString = (baseProps) => {
    winston.logEnter(JSON.stringify(baseProps));

    const siteUrl = new URL(baseProps.urlPath);

    if (siteUrl.protocol !== 'http:' && siteUrl.protocol !== 'https:') {
        let errorMessage = 'Support http and https protocol only!';

        winston.error(errorMessage);
        throw new Error(errorMessage);
    }

    // Remove port from url for 80 and 443 only
    let signatureUrl = "";
    if (siteUrl.port == "80" || siteUrl.port == "443" || siteUrl.port == "") {
        signatureUrl = `${siteUrl.protocol}//${siteUrl.hostname}${siteUrl.pathname}`;
    } else {
        signatureUrl = `${siteUrl.protocol}//${siteUrl.hostname}:${siteUrl.port}${siteUrl.pathname}`;
    }

    let defaultParams = ApiSigningUtil.getDefaultParam(baseProps);

    // add support to handle array in QueryString and name collision between queryString and formData
    let paramsArray = ApiSigningUtil.parseParams(defaultParams);

    // Found query string in url, transfer to params property
    if (siteUrl.search != null && siteUrl.search.length > 0) {
        let params = qs.parse(siteUrl.search.slice(1));
        paramsArray = paramsArray.concat(ApiSigningUtil.parseParams(params));
    }

    if (!_.isNil(baseProps.queryString)) {
        paramsArray = paramsArray.concat(ApiSigningUtil.parseParams(baseProps.queryString));
    }

    if (!_.isNil(baseProps.formData)) {
        paramsArray = paramsArray.concat(ApiSigningUtil.parseParams(baseProps.formData));
    }

    // Join name value pair with = (remove = if value is empty) and combine multiple name value pair with & 
    let stringParams = paramsArray.sort().map(element => {
        //Check if key value is present before appending with '='
        if (element.length > 1 && element[1] === '') {
            return element[0];
        } else {
            return element.join('=');
        }
    }).join('&');

    let sigBaseString = baseProps.httpMethod.toUpperCase() + '&' + signatureUrl + '&' + stringParams;

    winston.logExit(sigBaseString);
    return sigBaseString;
};

module.exports = ApiSigningUtil;