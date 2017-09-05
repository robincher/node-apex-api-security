'use strict'
const path = require('path');
const ApiSecurityUtil = require('../../lib/ApiSecurityUtil')
const ApiSecurityUtilStub = require('../stub/ApiSecurityUtilStub.json')

describe('ApiSecurityUtil APEX L1 Test', function () {

    let reqProps = ApiSecurityUtilStub.L1Req;
    let secHeader = ApiSecurityUtil.generateSecurityHeader(reqProps);

    it('APEX L1 - If timestamp and nonce are overwritten by run-time values', function () {
       expect(secHeader.timestamp).to.exists;
       expect(secHeader.nonce).to.exists;
    })

    it('APEX L1 - Signature , Signature Method and BaseString are generated', function () {
        expect(secHeader.signatureMethod).to.equal("HMACSHA256");
        expect(secHeader.baseString).to.exists;
        expect(secHeader.signature).to.exists;
    })

});

describe('ApiSecurityUtil APEX L2 Test', function () {

    let reqProps = ApiSecurityUtilStub.L2Req;
    reqProps.pemFileName = path.join(process.cwd(), reqProps.pemFileName )
    let secHeader = ApiSecurityUtil.generateSecurityHeader(reqProps);

    it('APEX L2 - If timestamp and nonce are overwritten by run-time default values', function () {
        expect(secHeader.timestamp).to.exists;
        expect(secHeader.nonce).to.exists;
    })

    it('APEX L2 - If app secret and pemfile are not overwritten by run-time default values', function () {
        expect(secHeader.secret).to.not.exists;
        expect(secHeader.pemFileName).to.not.equal(path.join(process.cwd() ,"./spec/cert/default.pem"));
    })

    it('APEX L2 - Signature and BaseString are generated', function () {
        expect(secHeader.signatureMethod).to.equal("SHA256withRSA");
        expect(secHeader.baseString).to.exists;
        expect(secHeader.signature).to.exists;
    })

});