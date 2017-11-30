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

ApiSigningUtil.getL1Signature = (message, secret) => {
    winston.logEnter(message, secret);

    if (isNullOrEmpty(message) || isNullOrEmpty(secret))
    {
        let compiled = _.template('<%= message %> and <%= secret %> must not be null or empty!');
        let errorMessage = compiled({ 'message': 'message', 'secret' : 'secret' });

        winston.error(errorMessage);
        throw new Error(errorMessage);
    }

    let token = crypto.createHmac('SHA256', secret).update(message).digest('base64');

    winston.logExit(token);
    return token;
}

ApiSigningUtil.verifyL1Signature = (signature, secret, message) => {
    winston.logEnter(signature, secret, message);

    let result = ApiSigningUtil.getL1Signature(message, secret);

    winston.logExit(signature == result);
    return signature == result;
}

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

ApiSigningUtil.getBaseString = (authPrefix, signatureMethod, appId, urlPath, httpMethod, formData, nonce, timestamp) => {
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
};


ApiSigningUtil.getSignatureToken = (reqProps) => {
    winston.logEnter(reqProps);

    let authPrefix = reqProps.authPrefix.toLowerCase();
    let signatureMethod = "HMACSHA256";
    let signature = '';

    // No Credentials L0
    if (reqProps.appId == null) return null;

    if (_.isNil(reqProps.secret)) {
        signatureMethod = "SHA256withRSA";
    }

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

    if (reqProps.secret != null)
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

ApiSigningUtil.getToken = (realm, authPrefix, httpMethod, urlPath, appId, secret, formJson, passphrase, certFileName, nonce, timestamp, certString) => {
    winston.logEnter(realm, authPrefix, httpMethod, urlPath, appId, secret, formJson, passphrase, certFileName, nonce, timestamp, certString);

    let apexPrefix = authPrefix.toLowerCase();

    if (isNullOrEmpty(nonce))
        apexNonce = nonceLib();
    else
        apexNonce = nonce;

    if (isNullOrEmpty(timestamp))
        apexTimestamp = (new Date).getTime();
    else
        apexTimestamp = timestamp;

    // No Credentials L0
    if (appId == null) return null;

    let signatureMethod = "HMACSHA256";
    if (secret == null) signatureMethod = "SHA256withRSA";

    let baseString = ApiSigningUtil.getBaseString(apexPrefix, signatureMethod, appId, urlPath, httpMethod, formJson, apexNonce, apexTimestamp);

    let signature = '';
    if (secret != null)
    {
        signature = ApiSigningUtil.getL1Signature(baseString, secret);
    }
    else
    {
        let privateKey = (certFileName ? ApiSigningUtil.getPrivateKeyFromPem(certFileName) : certString);
        signature = ApiSigningUtil.getL2Signature(baseString, privateKey, passphrase);
    }

    let token =
        apexPrefix.charAt(0).toUpperCase() + apexPrefix.slice(1) + " realm=\"" + realm + "\", " +
        apexPrefix + "_timestamp=\"" + apexTimestamp + "\", " +
        apexPrefix + "_nonce=\"" + apexNonce + "\", " +
        apexPrefix + "_app_id=\"" + appId + "\", " +
        apexPrefix + "_signature_method=\"" + signatureMethod + "\", " +
        apexPrefix + "_signature=\"" + signature + "\", " +
        apexPrefix + "_version=\"1.0\"";

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
 * @param {JSON} json JSON Object to be sorted
 *
 * @returns {JSON} Sorted JSON object
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