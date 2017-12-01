const nonceLib = require('nonce')();
const _ = require('lodash');
const qs = require('querystring');
const crypto = require('crypto');
const fs = require('fs');
const url = require('url');
const request = require('superagent');
const winston = require('./Logger');
const Promise = require('bluebird');

let ApiSigningUtil = {};

ApiSigningUtil.setLogLevel = (loglevel) => {
    winston.level = loglevel;
}


/**
 * Create HMAC256 Signature (L1) with a given message
 *
 * @param string message Message to be signed
 * @param string secret App's secret
 *
 * @returns string signature HMAC256 Signature
 * @public
 */
ApiSigningUtil.getL1Signature = (message, secret) => {
    winston.logEnter(message, secret);

    if (isNullOrEmpty(message) || isNullOrEmpty(secret))
    {
        let compiled = _.template('<%= message %> and <%= secret %> must not be null or empty!');
        let errorMessage = compiled({ 'message': 'message', 'secret' : 'secret' });

        winston.error(errorMessage);
        throw new Error(errorMessage);
    }

    let signature = crypto.createHmac('SHA256', secret).update(message).digest('base64');

    winston.logExit(signature);
    return signature;
}


/**
 * Verify HMAC256 Signature (L1)
 *
 * @param string signature Signature to be verified
 * @param string secret App's secret
 * @param string message Message to be signed
 *
 * @returns boolean Verification status
 * @public
 */
ApiSigningUtil.verifyL1Signature = (signature, secret, message) => {
    winston.logEnter(signature, secret, message);
    winston.logExit(_.isEqual(signature, ApiSigningUtil.getL1Signature(message, secret)));
    return _.isEqual(signature, ApiSigningUtil.getL1Signature(message, secret));
}


/**
 * Create RSA256 Signature (Lw) with a given message
 *
 * @param string message Message to be signed
 * @param string secret App's secret
 * @param string passphrase Passphrase
 *
 * @returns string signature RSA256 Signature
 * @public
 */
ApiSigningUtil.getL2Signature = (message, privateKey, passphrase) => {
    winston.logEnter(message, "privateKey***", "passphrase***");

    if (isNullOrEmpty(message) || (privateKey == null))
    {
        let compiled = _.template('<%= message %> and <%= privateKey %> must not be null or empty!');
        let errorMessage = compiled({ 'message': 'message', 'privateKey' : 'privateKey' });

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
}


/**
 * Verify RSA256 Signature (L2)
 *
 * @param string signature Signature to be verified
 * @param string publicKey Public Key
 * @param string message Message to be signed
 *
 * @returns boolean Verification status
 * @public
 */
ApiSigningUtil.verifyL2Signature = (signature, publicKey, message) => {
    winston.logEnter(signature, "publicKey***", message);

    if (isNullOrEmpty(message) || (publicKey == null))
    {
        let compiled = _.template('<%= message %> and <%= publicKey %> must not be null or empty!');
        let errorMessage = compiled({ 'message': 'message', 'publicKey' : 'publicKey' });

        winston.error(errorMessage);
        throw new Error(errorMessage);
    }

    let verifier = crypto.createVerify('sha256');
    verifier.update(message);
    let verifyResult = verifier.verify(publicKey, signature, 'base64');

    winston.logExit(verifyResult);
    return verifyResult;
}

ApiSigningUtil.getPrivateKeyFromPem = (pemFileName) => {
    winston.logEnterExit(pemFileName);

    return fs.readFileSync(pemFileName).toString('ascii');
}

ApiSigningUtil.getPublicKeyFromCer = (cerFileName) => {
    winston.logEnterExit(cerFileName);

    return fs.readFileSync(cerFileName).toString('ascii');
}

/*ApiSigningUtil.getBaseString = (authPrefix, signatureMethod, appId, urlPath, httpMethod, formData, nonce, timestamp) => {
    winston.logEnter(authPrefix, signatureMethod, appId, urlPath, httpMethod, formData, nonce, timestamp);

    let apexPrefix = authPrefix.toLowerCase();

    const siteUrl = url.parse(urlPath);
    //const originalUrl = siteUrl.href;

    if (siteUrl.protocol != "http:" && siteUrl.protocol != "https:")
    {
        let errorMessage = 'Support http and https protocol only!';

        winston.error(errorMessage);
        throw new Error(errorMessage);
    }

    // remove port from url
    const signatureUrl = siteUrl.protocol + "//" + siteUrl.hostname + siteUrl.pathname;
    //const port = siteUrl.port;
    winston.info('url:: %s', signatureUrl);

    let defaultParams = JSON.parse("{ " +
        "\"" + apexPrefix + "_app_id\" : \"" + appId + "\"," +
        "\"" + apexPrefix + "_nonce\": \"" + nonce + "\"," +
        "\"" + apexPrefix + "_signature_method\": \"" + signatureMethod + "\"," +
        "\"" + apexPrefix + "_timestamp\": " + timestamp + "," +
        "\"" + apexPrefix + "_version\": \"" + "1.0" + "\"" +
        "}");

    // found querystring in url, transfer to params property
    if (siteUrl.search != null && siteUrl.search.length > 0) {
        winston.info('QueryString:: %s', siteUrl.search);
        let params = qs.parse(siteUrl.search.slice(1));

        defaultParams = _.merge(defaultParams, params);
    }

    if (formData != null) defaultParams = _.merge(_.clone(formData), defaultParams);

    defaultParams = sortJson(defaultParams);

    let baseString = httpMethod.toUpperCase() + "&" + signatureUrl + "&" + qs.stringify(defaultParams, null, null, {encodeURIComponent: decodeURIComponent});

    winston.logExit(baseString);
    return baseString;
};*/

/**
 * Generate HTTP Authorize Signature Header for API Gateway
 *
 * @param object reqProps HTTP Signature request properties
 *
 * @returns string signatureToken HTTP Signature token to be append in Authorization header in HTTP
 * @public
 */
ApiSigningUtil.getSignatureToken = (reqProps) => {
    winston.logEnter(reqProps);

    // No Credentials L0
    if (reqProps.appId == null) return null;

    let authPrefix = reqProps.authPrefix.toLowerCase();
    let signature = '';
    let signatureMethod =  _.isNil(reqProps.secret) ? "SHA256withRSA" : "HMACSHA256";

    let baseProps = {
        "authPrefix": authPrefix.toLowerCase(),
        "signatureMethod" : signatureMethod,
        "appId" : reqProps.appId,
        "urlPath" : reqProps.urlPath,
        "httpMethod" : reqProps.httpMethod,
        "formData" : reqProps.formData,
        "nonce" : isNullOrEmpty(reqProps.nonce) ? nonceLib() : reqProps.nonce,
        "timestamp" : isNullOrEmpty(reqProps.timestamp) ? (new Date).getTime() : reqProps.timestamp

    }

    let baseString = ApiSigningUtil.getSignatureBaseString(baseProps);

    if (!_.isNil(reqProps.secret))
    {
        signature = ApiSigningUtil.getL1Signature(baseString, reqProps.secret);
    }
    else
    {
        let privateKey = (reqProps.certFileName ? ApiSigningUtil.getPrivateKeyFromPem(reqProps.certFileName) : reqProps.certString);
        signature = ApiSigningUtil.getL2Signature(baseString, privateKey, reqProps.passphrase);
    }

    let signatureToken =
        authPrefix.charAt(0).toUpperCase() + authPrefix.slice(1) + " realm=\"" + reqProps.realm + "\", " +
        authPrefix + "_timestamp=\"" + baseProps.timestamp + "\", " +
        authPrefix + "_nonce=\"" + baseProps.nonce + "\", " +
        authPrefix + "_app_id=\"" + baseProps.appId + "\", " +
        authPrefix + "_signature_method=\"" + baseProps.signatureMethod + "\", " +
        authPrefix + "_signature=\"" + signature + "\", " +
        authPrefix + "_version=\"1.0\"";

    winston.logExit(signatureToken);
    return signatureToken;

};


/**
 * Formulate Signature base string
 *
 * @param object baseProps Base string formulation request properties in JSON object
 *
 * @returns string sigBaseString Signature base string for signing
 * @public
 */
ApiSigningUtil.getSignatureBaseString = (baseProps) => {
    winston.logEnter(baseProps);

    const siteUrl = url.parse(baseProps.urlPath);

    //const originalUrl = siteUrl.href;

    if (siteUrl.protocol != "http:" && siteUrl.protocol != "https:")
    {
        let errorMessage = 'Support http and https protocol only!';

        winston.error(errorMessage);
        throw new Error(errorMessage);
    }

    // remove port from url
    const signatureUrl = siteUrl.protocol + "//" + siteUrl.hostname + siteUrl.pathname;
    //const port = siteUrl.port;
    winston.info('url:: %s', signatureUrl);

    let defaultParams = JSON.parse("{ " +
        "\"" + baseProps.authPrefix.toLowerCase() + "_app_id\" : \"" + baseProps.appId + "\"," +
        "\"" + baseProps.authPrefix.toLowerCase() + "_nonce\": \"" + baseProps.nonce + "\"," +
        "\"" + baseProps.authPrefix.toLowerCase() + "_signature_method\": \"" + baseProps.signatureMethod + "\"," +
        "\"" + baseProps.authPrefix.toLowerCase() + "_timestamp\": " + baseProps.timestamp + "," +
        "\"" + baseProps.authPrefix.toLowerCase() + "_version\": \"" + "1.0" + "\"" +
        "}");

    // found querystring in url, transfer to params property
    if (siteUrl.search != null && siteUrl.search.length > 0) {
        winston.info('QueryString:: %s', siteUrl.search);
        let params = qs.parse(siteUrl.search.slice(1));

        defaultParams = _.merge(defaultParams, params);
    }

    if (!_.isNil(baseProps.formData)) {
        defaultParams = _.merge(_.clone(baseProps.formData), defaultParams);
    }

    defaultParams = sortJson(defaultParams);

    let sigBaseString = baseProps.httpMethod.toUpperCase() + "&" + signatureUrl + "&" + qs.stringify(defaultParams, null, null, {encodeURIComponent: decodeURIComponent});

    winston.logExit(sigBaseString);
    return sigBaseString;
};

ApiSigningUtil.getTokenFromSecret = (realm, authPrefix, httpMethod, urlPath, appId, secret, formJson, nonce, timestamp) => {
    return ApiSigningUtil.getToken(realm, authPrefix, httpMethod, urlPath, appId, secret, formJson, null, null, nonce, timestamp, null);
}

ApiSigningUtil.getTokenFromCertFileName = (realm, authPrefix, httpMethod, urlPath, appId, formJson, passphrase, certFileName, nonce, timestamp) => {
    return ApiSigningUtil.getToken(realm, authPrefix, httpMethod, urlPath, appId, null, formJson, passphrase, certFileName, nonce, timestamp, null);
}

ApiSigningUtil.getTokenFromCertString = (realm, authPrefix, httpMethod, urlPath, appId, formJson, passphrase, certString, nonce, timestamp) => {
    return ApiSigningUtil.getToken(realm, authPrefix, httpMethod, urlPath, appId, null, formJson, passphrase, null, nonce, timestamp, certString);
}

/**
 * Generate HTTP Authorize Signature Header for API Gateway (Deprecated)
 * Legacy interface to be deprecated, please change to getSignatureToken instead
 *
 * @param string realm
 * @param string authPrefix
 * @param string httpMethod
 * @param string urlPath
 * @param string appId
 * @param string secret
 * @param object formData x-url-encode form data fields in JSON object
 * @param string passphrase Signing certificate file or contents's passphrase
 * @param string certFileName Certificate file path
 * @param string nonce Random nonce for base string formulation
 * @param string timestamp Timestamp
 * @param string certString Signing certificate contents
 *
 * @returns string token HTTP Signature token to be append in Authorization header in HTTP
 * @public
 */

ApiSigningUtil.getToken = (realm, authPrefix, httpMethod, urlPath, appId, secret, formData, passphrase, certFileName, nonce, timestamp, certString) => {
    winston.logEnter(realm, authPrefix, httpMethod, urlPath, appId, secret, formData, passphrase, certFileName, nonce, timestamp, certString);
    // No Credentials L0
    if (appId == null) return null;

    let signature = '';
    let signatureMethod =  _.isNil(secret) ? "SHA256withRSA" : "HMACSHA256";

    let baseProps = {
        "authPrefix": authPrefix.toLowerCase(),
        "signatureMethod": signatureMethod,
        "appId": appId,
        "urlPath": urlPath,
        "httpMethod": httpMethod,
        "formData": isNullOrEmpty(formData) ? null: formData,
        "nonce": isNullOrEmpty(nonce) ? nonceLib() : nonce,
        "timestamp": isNullOrEmpty(timestamp) ? (new Date).getTime() :timestamp
    }

    let baseString = ApiSigningUtil.getSignatureBaseString(baseProps);

    //let baseString = ApiSigningUtil.getBaseString(apexPrefix, signatureMethod, appId, urlPath, httpMethod, formData, apexNonce, apexTimestamp);

    if (!_.isNil(secret))
    {
        signature = ApiSigningUtil.getL1Signature(baseString, secret);
    }
    else
    {
        let privateKey = (certFileName ? ApiSigningUtil.getPrivateKeyFromPem(certFileName) : certString);
        signature = ApiSigningUtil.getL2Signature(baseString, privateKey, passphrase);
    }

    let token =
        baseProps.authPrefix.charAt(0).toUpperCase() + baseProps.authPrefix.slice(1) + " realm=\"" + realm + "\", " +
        baseProps.authPrefix + "_timestamp=\"" + baseProps.timestamp + "\", " +
        baseProps.authPrefix + "_nonce=\"" + baseProps.nonce + "\", " +
        baseProps.authPrefix + "_app_id=\"" + baseProps.appId + "\", " +
        baseProps.authPrefix + "_signature_method=\"" + signatureMethod + "\", " +
        baseProps.authPrefix + "_signature=\"" + signature + "\", " +
        baseProps.authPrefix + "_version=\"1.0\"";

    winston.logExit(token);
    return token;
}

ApiSigningUtil.makeHttpRequest = (urlPath, token, formData, httpMethod, port) => {
    return new Promise(function(resolve, reject){
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
        const targetURL = url.parse(urlPath);

        // restore the port no remove during validation
        if (isNullOrEmpty(port)) port = 443;
        targetURL.port = port;

        let httpReq = request(httpMethod, targetURL.href);

        if (token != undefined && token.length > 0) {
            httpReq = httpReq.set("Authorization", token);
        }

        if (httpMethod == "POST" ||httpMethod == "PUT" && formData != undefined) {
            let postData = qs.stringify(formData, null, null, {encodeURIComponent: decodeURIComponent});
            httpReq = httpReq
            .type("application/x-www-form-urlencoded")
            .set("Content-Length", Buffer.byteLength(postData))
            .send(postData);
        }

        httpReq.end(function (err, res) {
            if (!err) {
                resolve(res);
            } else {
                reject(err);
            }
        });
    });
}

function isNullOrEmpty(data)
{
    return !data;
}

/**
 * Sorts a JSON object based on the key value in alphabetical order
 *
 * @param object json JSON Object to be sorted
 *
 * @returns object Sorted JSON object
 * @private
 */
function sortJson(json) {
    if (_.isNil(json)) {
        return json;
    }

    let newJSON = {};
    let keys = Object.keys(json);
    keys.sort();

    for (key in keys) {
        newJSON[keys[key]] = json[keys[key]];
    }
    return newJSON;
};

module.exports = ApiSigningUtil;