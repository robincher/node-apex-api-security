const nonce = require('nonce')();
const _ = require('lodash');
const qs = require('querystring');
const crypto = require('crypto');
const fs = require('fs');
const url = require('url');
const request = require('superagent');

let defaultProps = {
    "prefix": undefined,
    "method": "get",
    "url": undefined,
    "appid": undefined,
    "secret": undefined,
    "nonce": "",
    "timestamp": "",
    "version": "1.0",
    "params": {},
    "formData": {},
    "pemFileName": "./spec/cert/default.pem",
    "passphrase": "password",
    "signatureMethod": "",
    "baseString": "",
    "signature": "",
    "token": "",
    "errorMessage": "",
    nextHop: undefined
}

let ApiSecurityUtil = {};

/**
 * Test Authorize Header Generator for APEX
 *
 * @param {JSON} reqProps HTTP Authorize request properties
 *
 * @returns {String} Auth header output
 * @public
 */
ApiSecurityUtil.test = (reqProps) => {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    const targetURL = url.parse(reqProps.url);

    // restore the port no remove during validation
    targetURL.port = reqProps.port;

    // construct query string
    if (reqProps.params != undefined) {
        let queryString = qs.stringify(reqProps.params, null, null, {encodeURIComponent: decodeURIComponent});
        targetURL.search = queryString;
    }

    let httpReq = request(reqProps.method, targetURL.href);

    if (reqProps.token != undefined && reqProps.token.length > 0) {
        httpReq = httpReq.set("Authorization", getAuthorizationToken(reqProps));
    }

    if (reqProps.method == "POST" ||reqProps.method == "PUT" && reqProps.formData != undefined) {
        let postData = qs.stringify(reqProps.formData, null, null, {encodeURIComponent: decodeURIComponent});
        httpReq = httpReq
            .type("application/x-www-form-urlencoded")
            .set("Content-Length", Buffer.byteLength(postData))
            .send(postData);
    }

    httpReq.end(function (err, res) {
        reqProps.responseCode = res.status;
        if (res.ok) {
            reqProps.responseData = JSON.stringify(res.body);
        } else {
            addMessage(reqProps, err.message);
        }

        printSecurityHeader(reqProps);
    });
}

/**
 * Generate HTTP Authorize Security Header for APEX
 *
 * @param {JSON} reqProps HTTP Authorize request properties
 *
 * @returns {JSON} Request Property with additional signature value
 * @public
 */
ApiSecurityUtil.generateSecurityHeader = (reqProps) => {
    reqProps = initRequestProps(defaultProps, reqProps);

    // No Credentials L0
    if (reqProps.appid == undefined) return reqProps;

    if (reqProps.secret != undefined) {
        reqProps.signatureMethod = "HMACSHA256";
    } else {
        reqProps.signatureMethod = "SHA256withRSA";
    }


    let defaultParams = JSON.parse("{ " +
        "\"" + reqProps.prefix + "_app_id\" : \"" + reqProps.appid + "\"," +
        "\"" + reqProps.prefix + "_nonce\": " + reqProps.nonce + "," +
        "\"" + reqProps.prefix + "_signature_method\": \"" + reqProps.signatureMethod + "\"," +
        "\"" + reqProps.prefix + "_timestamp\": " + reqProps.timestamp + "," +
        "\"" + reqProps.prefix + "_version\": \"" + reqProps.version + "\"" +
        "}");

    //Remove undefined or null query params from signing
    if(!_.isNil(reqProps.params)) {
        reqProps.params = _.pickBy(reqProps.params, _.identity);
    }

    // merge default parameters with query/body params and sort alphabetically.
    let baseParams = sortJSON(_.merge(defaultParams, reqProps.params));

    if (reqProps.method == "POST" || reqProps.method == "PUT" || reqProps.method == "PATCH") {
        baseParams = sortJSON(_.merge(baseParams, reqProps.formData));
    }

    // base string required by crypto to hash and sign the signature token for APEX API gateway
    reqProps.baseString = reqProps.method.toUpperCase() + "&" + reqProps.url + "&" +
        qs.stringify(baseParams, null, null, {encodeURIComponent: decodeURIComponent});

    // APEX L2 RSA256 Signing if App Secret undefined
    if (reqProps.secret == undefined) {
        // Load pem file containing the x509 cert & private key & sign the base string with it.
        let pk = fs.readFileSync(reqProps.pemFileName).toString('ascii');
        reqProps.signature = crypto.createSign('RSA-SHA256')
            .update(reqProps.baseString)
            .sign({
                key: pk,
                passphrase: reqProps.passphrase
            }, 'base64');
    }
    else {
        // APEX L1 HMAC256 Signing if App Secret is present
        reqProps.signature = crypto.createHmac('SHA256', reqProps.secret).update(reqProps.baseString).digest('base64');
    }

    reqProps.token =
        reqProps.prefix.charAt(0).toUpperCase() + reqProps.prefix.slice(1) + " realm=\"" + reqProps.url + "\"," +
        reqProps.prefix + "_timestamp=\"" + reqProps.timestamp + "\"," +
        reqProps.prefix + "_nonce=\"" + reqProps.nonce + "\"," +
        reqProps.prefix + "_app_id=\"" + reqProps.appid + "\"," +
        reqProps.prefix + "_signature_method=\"" + reqProps.signatureMethod + "\"," +
        reqProps.prefix + "_signature=\"" + reqProps.signature + "\"," +
        reqProps.prefix + "_version=\"1.0\"";

    // Verify if next hop security auth header is required
    if (reqProps.nextHop != undefined) {
        // propagate the method, params and formData to nexthop
        reqProps.nextHop.method = reqProps.method;
        reqProps.nextHop.params = reqProps.params;
        reqProps.nextHop.formData = reqProps.formData;
        reqProps.nextHop = ApiSecurityUtil.generateSecurityHeader(reqProps.nextHop);
    }

    return reqProps;
}


/**
 * Get HTTP Authorization header value
 *
 * @param {JSON} reqProps HTTP Authorize request properties
 *
 * @returns {String} Request Property with additional signature value
 * @public
 */
ApiSecurityUtil.getSecurityToken = (reqProps) => {
    return getAuthorizationToken(ApiSecurityUtil.generateSecurityHeader(reqProps));
}



/**
 * Method that extract Authorization header value from the generated request property
 *
 * @param {JSON} reqProps HTTP Authorize request properties
 *
 * @return {String} authToken Authorization Header value
 * @private
 */
function getAuthorizationToken(reqProps) {
    let authToken = "";
    if (reqProps.token != undefined && reqProps.token.length > 0) {
        authToken = reqProps.token;
    }

    // process nextHop
    if (reqProps.nextHop != undefined) {
        if (authToken.length == 0)
            authToken += getAuthorizationToken(reqProps.nextHop);
        else
            authToken += ", " + getAuthorizationToken(reqProps.nextHop);
    }
    return authToken;
}


/**
 * Get Base string that is used to signed when generating the signature
 *
 * @param {JSON} reqProps HTTP Authorize request properties
 *
 * @return {String} baseString Base String for signing
 * @private
 */
function getBaseString(reqProps) {
    let baseString = "";

    if (reqProps.appid != undefined) baseString = "\n-->" + reqProps.baseString;

    // process nextHop
    if (reqProps.nextHop != undefined) {
        baseString += getBaseString(reqProps.nextHop);
    }
    return baseString;
}

/**
 * Console print out generated HTTP Authorization security header
 *
 * @param {JSON} reqProps HTTP Authorize request properties
 *
 * @private
 */
function printSecurityHeader(reqProps) {
    console.log("");
    console.log("URL:::" + reqProps.url);

    let baseString = getBaseString(reqProps);
    if (baseString.length > 0)
        console.log("baseString:::" + baseString);

    let token = getAuthorizationToken(reqProps);
    if (token.length > 0)
        console.log("token:::\n" + token);

    console.log("");
    console.log("");
    console.log("responseCode:::" + reqProps.responseCode);

    if (reqProps.errorMessage != undefined && reqProps.errorMessage.length > 0)
        console.log("errorMessage:::" + reqProps.errorMessage);

    if (reqProps.responseData != undefined)
        console.log("responseData:::" + reqProps.responseData);

    console.log("");
}


/**
 * Add error message to request property
 *
 * @param {JSON} reqProps HTTP Authorize request properties
 * @param {String} message Error response message
 *
 * @private
 */
function addMessage(reqProps, message) {
    reqProps.errorMessage += message + "\n";
}

/**
 * Populate default values if it is undefined in the original request
 *
 * @param {JSON} reqProps HTTP Authorize request properties
 *
 * @returns {JSON} Initialized request properties
 * @private
 */
function initRequestProps(defaultProps, reqProps) {
    if (reqProps.prefix == undefined) reqProps.prefix = defaultProps.prefix;
    if (reqProps.method == undefined) reqProps.method = defaultProps.method;
    if (reqProps.url == undefined) reqProps.url = defaultProps.url;

    if (reqProps.appid == undefined) reqProps.appid = defaultProps.appid;

    if (reqProps.secret == undefined && defaultProps != undefined) reqProps.secret = defaultProps.secret;

    if (reqProps.nonce == undefined) reqProps.nonce = nonce();
    if (reqProps.timestamp == undefined) reqProps.timestamp = (new Date).getTime();
    if (reqProps.version == undefined) reqProps.version = defaultProps.version;

    if (reqProps.params == undefined) reqProps.params = defaultProps.params;
    if (reqProps.formData == undefined) reqProps.formData = defaultProps.formData;

    if (reqProps.pemFileName == undefined) reqProps.pemFileName = defaultProps.pemFileName;
    if (reqProps.passphrase == undefined) reqProps.passphrase = defaultProps.passphrase;

    return validateProps(reqProps);
}

/**
 * Validate the request properties by removing the port number
 * and transferring query parameters to params property in the request json
 *
 * @param {JSON} reqProps HTTP Authorize request properties
 *
 * @returns {JSON} Validated request properties
 * @private
 */
function validateProps(reqProps) {
    reqProps.errorMessage = "";

    if (reqProps.url != undefined) {
        const targetURL = url.parse(reqProps.url);
        const originalUrl = targetURL.href;

        // found querystring in url, transfer to params property
        if (targetURL.search != null && targetURL.search.length > 0) {
            let params = qs.parse(targetURL.search.slice(1));
            reqProps.params = _.merge(reqProps.params, params);
        }

        // remove port from url
        reqProps.url = targetURL.protocol + "//" + targetURL.hostname + targetURL.pathname;
        reqProps.port = targetURL.port;

        if (originalUrl != reqProps.url) addMessage(reqProps, "Warning:: Change URL from '" + originalUrl + "' to '" + reqProps.url + "'");
    }

    if (reqProps.method != undefined) {
        const supportedMethods = "|GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|";
        reqProps.method = reqProps.method.toUpperCase();

        if (supportedMethods.indexOf("|" + reqProps.method + "|") == -1) {
            // error, invalid http method
            addMessage(reqProps, "Error:: Method must be one of the following keywords (" + supportedMethods + ")");
        }
    }
    return reqProps;
}

/**
 * Sorts a JSON object based on the key value in alphabetical order
 *
 * @param {JSON} json JSON Object to be sorted
 *
 * @returns {JSON} Sorted JSON object
 * @private
 */
function sortJSON(json) {
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

module.exports = ApiSecurityUtil;