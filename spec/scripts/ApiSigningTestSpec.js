'use strict';
const _ = require('lodash');
const path = require('path');
const util = require('util');

const apiHelper = require('../../lib/ApiSigningUtil');

const BasePath = '../../node_modules/test-suites-apex-api-security/';
const CertPath = './node_modules/test-suites-apex-api-security/';

const NODEJS = 'nodejs';

apiHelper.setLogLevel('none');

let params = {};
let testDescription = 'Test';

/** test helper function **/
function perfromTest(desc, params, errorTest, normalTest) {
    describe(desc, function() {
        _.forEach(params, (param) => {
            if (!(param.skipTest && param.skipTest.includes(NODEJS))) {
                it(param.id + ". " + param.description, function() {
                    param.apiParam.urlPath = param.apiParam.signatureUrl;
                    if (param.errorTest) {
                        errorTest(param);
                    } else {
                        let result = normalTest(param);
                        expect(String(result)).to.equal(getExpectedResult(param));        
                    }
                });
            }
        });
    });
}

function getExpectedResult(param) {
    return param.expectedResult.nodejs !== undefined ? param.expectedResult.nodejs : param.expectedResult;
}

function setExpectedResult(param, newValue) {
    if (param.expectedResult.nodejs === undefined) {
        param.expectedResult = newValue;
    }
    else{
        param.expectedResult.nodejs = newValue;
    }
}

/** Test Cases **/
params = require(BasePath + 'testData/defaultParams.json');
testDescription = 'getDefaultParam Test';
perfromTest(testDescription, params, null, (param) => {
    let result = '';
    let dynamicTimestamp = false;
    let dynamicNonce = false;

    if (param.apiParam.timestamp === undefined || param.apiParam.timestamp === "") {
        dynamicTimestamp = true;
    }
   
    if (param.apiParam.nonce === undefined || param.apiParam.nonce === "") {
        dynamicNonce = true;
    }

    let defaultParams = apiHelper.getDefaultParam(param.apiParam);

    // timestamp value not set in input param, update the expected result after getDefaultParam set the value
    if (dynamicTimestamp) {
        setExpectedResult(param, util.format(getExpectedResult(param), param.apiParam.timestamp));
    }
    if (dynamicNonce) {
        setExpectedResult(param, util.format(getExpectedResult(param), param.apiParam.nonce));
    }

    let keys = Object.keys(defaultParams);
    keys.forEach(function(key){
        result = result + "&" + key + "=" + defaultParams[key];
    });

    return result;
} );

params = require(BasePath + 'testData/getL1Signature.json');
testDescription = 'getHMACSignature Test';
perfromTest(testDescription, params, (param) => {
    expect(apiHelper.getHMACSignature
        .bind(apiHelper, param.message, param.apiParam.secret))
        .to.throw(getExpectedResult(param));
}, (param) => {
    return apiHelper.getHMACSignature(param.message, param.apiParam.secret);
});


params = require(BasePath + 'testData/verifyL1Signature.json');
testDescription = 'verifyHMACSignature Test';
perfromTest(testDescription, params, null, (param) => {
    return String(apiHelper.verifyHMACSignature(param.apiParam.signature, param.apiParam.secret, param.message));
} );


params = require(BasePath + 'testData/getL2Signature.json');
testDescription = 'getRSASignature Test';
perfromTest(testDescription, params, (param) => {
    expect(getRSASignature
        .bind(this, param.message, param.apiParam.passphrase, param.apiParam.privateCertFileName))
        .to.throw(getExpectedResult(param));
}, (param) => {
    return getRSASignature(param.message, param.apiParam.passphrase, param.apiParam.privateCertFileName);
});

function getRSASignature(message, passphrase, privateCertFileName) {
    let privateKey = apiHelper.getPrivateKeyFromPem(
        path.join(CertPath, privateCertFileName)
    );

    let result = apiHelper.getRSASignature(message, privateKey, passphrase);

    return result;
}

params = require(BasePath + 'testData/verifyL2Signature.json');
testDescription = 'verifyL2Signature Test';
perfromTest(testDescription, params, (param) => {
    expect(verifyL2Signature
        .bind(this, param))
        .to.throw(getExpectedResult(param));
}, (param) => {
    return verifyL2Signature(param);
} );

function verifyL2Signature(param){
    let publicKey = apiHelper.getPublicKeyFromCer(
        path.join(CertPath, param.publicCertFileName));

    let result = String(apiHelper.verifyRSASignature(param.apiParam.signature, publicKey, param.message));

    return result;
}

params = require(BasePath + 'testData/getSignatureBaseString.json');
testDescription = 'getSignatureBaseString Test';
perfromTest(testDescription, params, null, (param) => {
    return apiHelper.getSignatureBaseString(param.apiParam);
} );

params = require(BasePath + 'testData/getSignatureToken.json');
testDescription = 'getSignatureToken Test';
perfromTest(testDescription, params, (param) => {
    if (param.apiParam.privateCertFileName !== undefined) {
        param.apiParam.certFileName = path.join(CertPath, param.apiParam.privateCertFileName);
    }
    expect(apiHelper.getSignatureToken
        .bind(apiHelper, param.apiParam))
        .to.throw(getExpectedResult(param));
}, (param) => {
    if (param.apiParam.privateCertFileName !== undefined) {
        param.apiParam.certFileName = path.join(CertPath, param.apiParam.privateCertFileName);
    }

    let dynamicTimestamp = false;
    if (param.apiParam.timestamp === undefined || param.apiParam.timestamp === '') {
        dynamicTimestamp = true;
    }

    let dynamicNonce = false;
    if (param.apiParam.nonce == undefined || param.apiParam.nonce == "") {
        dynamicNonce = true;
    }

    let result = apiHelper.getSignatureToken(param.apiParam);

    if (dynamicTimestamp && dynamicNonce) {
        //console.log(">>> timestamp %s, nonce %s <<<", param.apiParam.timestamp, param.apiParam.nonce)

        setExpectedResult(param, util.format(getExpectedResult(param), param.apiParam.nonce, param.apiParam.timestamp, param.apiParam.signature))
    } else if (dynamicTimestamp) {
        //console.log(">>> timestamp %s <<<", param.apiParam.timestamp)

        setExpectedResult(param, util.format(getExpectedResult(param), param.apiParam.timestamp, param.apiParam.signature))
    } else if (dynamicNonce) {
        //console.log(">>> nonce %s <<<", param.apiParam.nonce)

        setExpectedResult(param, util.format(getExpectedResult(param), param.apiParam.nonce, param.apiParam.signature))
    }
    return result;
});