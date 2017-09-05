'use strict'
const path = require('path');
const ApexAuthorizationUtil  = require('../../lib/ApexAuthorizationUtil');

//ApexAuthorizationUtil.setLogLevel('trace');
ApexAuthorizationUtil.setLogLevel('none');

describe('ApexAuthorization L1 Test', function () {
    var secret = 'secret';
    var message = 'message';
    var expectedResult = 'i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs=';
    var expectedErrMsg = 'message and secret must not be null or empty!';

    it('APEX L1 - message is null or empty', function () {
        expect(ApexAuthorizationUtil.getApexL1Signature.bind(ApexAuthorizationUtil, undefined, secret)).to.throw(expectedErrMsg);
        expect(ApexAuthorizationUtil.getApexL1Signature.bind(ApexAuthorizationUtil, null, secret)).to.throw(expectedErrMsg);
        expect(ApexAuthorizationUtil.getApexL1Signature.bind(ApexAuthorizationUtil, '', secret)).to.throw(expectedErrMsg);
    });

    it('APEX L1 - Secret is null or empty', function () {
        expect(ApexAuthorizationUtil.getApexL1Signature.bind(ApexAuthorizationUtil, message)).to.throw(expectedErrMsg);
        expect(ApexAuthorizationUtil.getApexL1Signature.bind(ApexAuthorizationUtil, message, null)).to.throw(expectedErrMsg);
        expect(ApexAuthorizationUtil.getApexL1Signature.bind(ApexAuthorizationUtil, message, "")).to.throw(expectedErrMsg);
    });

    it('APEX L1 - Verify Signature', function () {
        let verifyResult = ApexAuthorizationUtil.verifyApexL1Signature(expectedResult, secret, message);
        expect(verifyResult).to.equal(true);
    });

    it('APEX L1 - Verify Signature with wrong secret', function () {
        let result = ApexAuthorizationUtil.verifyApexL1Signature(expectedResult, secret + 'x', message);
        expect(result).to.equal(false);
    });

    it('APEX L1 - Verify Signature with wrong message', function () {
        let result = ApexAuthorizationUtil.verifyApexL1Signature(expectedResult, secret, message + 'x');
        expect(result).to.equal(false);
    });

    it('APEX L1 - Message with standard ASCII', function () {
        let message = 'Lorem ipsum dolor sit amet, vel nihil senserit ei. Ne quo erat feugait disputationi.';
        let result = ApexAuthorizationUtil.getApexL1Signature(message, secret);
        expect(result).to.equal("cL3lY5/rhmkxMw/dCHCa4b9Lpp/soPPACnIxtQwRQI8=");
    });

    it('APEX L1 - Message with UTF8 (Chinese Traditional)', function () {
        let message = '道続万汁国圭絶題手事足物目族月会済。';
        let result = ApexAuthorizationUtil.getApexL1Signature(message, secret);
        expect(result).to.equal("wOHv68zuoiIjfJHW0hZcOk4lORyiAL/IGK8WSkBUnuk=");
    });

    it('APEX L1 - Message with UTF8 (Japanese)', function () {
        let message = '員ちぞど移点お告周ひょ球独狙チウソノ法保断フヒシハ東5広みぶめい質創ごぴ採8踊表述因仁らトつ。';
        let result = ApexAuthorizationUtil.getApexL1Signature(message, secret);
        expect(result).to.equal("L0ft4O8R2hxpupJVkLbgQpW0+HRw3KDgNUNf9DAEY7Y=");
    });

    it('APEX L1 - Message with UTF8 (Korean)', function () {
        let message = '대통령은 즉시 이를 공포하여야 한다, 그 자율적 활동과 발전을 보장한다.';
        let result = ApexAuthorizationUtil.getApexL1Signature(message, secret);
        expect(result).to.equal("a6qt0t/nQ3GQFAEVTH+LMvEi0D41ZaKqC7LWJcVmHlE=");
    });

    it('APEX L1 - Message with UTF8 (Greek)', function () {
        let message = 'Λορεμ ιπσθμ δολορ σιτ αμετ, τατιον ινιμιcθσ τε ηασ, ιν εαμ μοδο ποσσιμ ινvιδθντ.';
        let result = ApexAuthorizationUtil.getApexL1Signature(message, secret);
        expect(result).to.equal("WUGjbeO8Jy8Rvs5tD2biLHPR0+qtAmXeZKqX6acYL/4=");
    });
});


describe('ApexAuthorization L2 Test', function () {
    var pemFileName = 'spec/cert/alpha.apex.gov.sg.pem';
    var alphaFileName = 'spec/cert/alpha.apex.gov.sg.cer';
    var betaFileName = 'spec/cert/beta.apex.gov.sg.cer';
    var privateKey = ApexAuthorizationUtil.getPrivateKeyFromPem(path.join(process.cwd(), pemFileName));
    var publicKey = ApexAuthorizationUtil.getPublicKeyFromCer(path.join(process.cwd(), alphaFileName));
    var passphrase = 'passwordkey';
    
    var expectedSignature = "o6Z6W8JzBgxjq1WpW7l4LR8rVWyl8wHAPrPkCJ9Jmz1P3jX4EmF+4e7+X8dX4JDQzxrAVErGJb15DpqGDnYfhozCIm68UswYEKsUFRJTC1X7cFDSP6WcIjBU9tfw1BBYQdLK5EzzXKudXayRSq2E6a9Pqlu0UodMjJpkdyT5HnOKzs+ao72tloJROctBGsE8rX/rURrhx5qVWJg1jnn8GbOexPHTvaM5vzdWMwFfNKPjBXYj1YwmCt+EFBb2W9pvKzIVsCQ5M+r2hNl2FRInq41v61xpiwMSLxpHdDXz7YYZtSByWH7/0mjwt86EPwkes9Bj5AOO6ZXUjuDiyGAjUQ==";
    var message = 'Lorem ipsum dolor sit amet, vel nihil senserit ei. Ne quo erat feugait disputationi.';
    var expectedGetErrMsg = 'message and privateKey must not be null or empty!';
    var expectedVerifyErrMsg = 'message and publicKey must not be null or empty!';

    it('APEX L2 - Message is null or empty', function () {
        expect(ApexAuthorizationUtil.getApexL2Signature.bind(ApexAuthorizationUtil, undefined, privateKey)).to.throw(expectedGetErrMsg);
        expect(ApexAuthorizationUtil.getApexL2Signature.bind(ApexAuthorizationUtil, null, privateKey)).to.throw(expectedGetErrMsg);
        expect(ApexAuthorizationUtil.getApexL2Signature.bind(ApexAuthorizationUtil, '', privateKey)).to.throw(expectedGetErrMsg);
    });

    it('APEX L2 - PrivateKey is null or undefined', function () {
        expect(ApexAuthorizationUtil.getApexL2Signature.bind(ApexAuthorizationUtil, message)).to.throw(expectedGetErrMsg);
        expect(ApexAuthorizationUtil.getApexL2Signature.bind(ApexAuthorizationUtil, message, null)).to.throw(expectedGetErrMsg);
    });

    it('APEX L2 - Verify Signature', function () {
        var verifyResult = ApexAuthorizationUtil.verifyApexL2Signature(expectedSignature, publicKey, message);
        expect(verifyResult).to.equal(true);
    });

    it('APEX L2 - Verify Signature with null PublicKey', function () {
        expect(ApexAuthorizationUtil.verifyApexL2Signature.bind(ApexAuthorizationUtil, expectedSignature, null, message)).to.throw(expectedVerifyErrMsg);
    });

    it('APEX L2 - Verify Signature with null message', function () {
        expect(ApexAuthorizationUtil.verifyApexL2Signature.bind(ApexAuthorizationUtil, expectedSignature, publicKey, null)).to.throw(expectedVerifyErrMsg);
        expect(ApexAuthorizationUtil.verifyApexL2Signature.bind(ApexAuthorizationUtil, expectedSignature, publicKey, '')).to.throw(expectedVerifyErrMsg);
    });

    it('APEX L2 - Verify Signature with wrong cert', function () {
        let wrongPublicKey = ApexAuthorizationUtil.getPublicKeyFromCer(path.join(process.cwd(), betaFileName));
        let verifyResult = ApexAuthorizationUtil.verifyApexL2Signature(expectedSignature, wrongPublicKey, message);
        expect(verifyResult).to.equal(false);
    });

    it('APEX L2 - Verify Signature with wrong message', function () {
        let verifyResult = ApexAuthorizationUtil.verifyApexL2Signature(expectedSignature, publicKey, message + 'x');
        expect(verifyResult).to.equal(false);
    });

    it('APEX L2 - Message with standard ASCII', function () {
        let signature = ApexAuthorizationUtil.getApexL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal(expectedSignature);
    });

    it('APEX L2 - Message with UTF8 (Chinese Traditional)', function () {
        let message = '道続万汁国圭絶題手事足物目族月会済。';
        let signature = ApexAuthorizationUtil.getApexL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal("aUl0Oo0TBpfKQXcbLSJHTA6DjgSmTH3Fn/01YcPG0oM1w68+orizcuSxsCpRfAbc7IDxizuMivQpUm5abwbuyQlLNNy3oH7v0jT29+MkqoeMdDfOlGZZyxb8rZZn5j1N8+k5Y8/Kn0CTk/GQrL/5IYcIXKc/W8lOxnxRBuzENxNz1QgdecordhW/1IQrcAnLlt5dFXGdCRXFkWDd1FwKs7e3+154cQgwWdFOw7AzqnjDpTrIYlDsSdHCtqjU72PxHW6jCBS2NG6VNeplH6EKjqmVD+M1op+k3QJeKnP7LsWbk0ngneX0GEXSrYtCkDEfqxCFmtOFdsGRBVRw+cAU6A==");
    });

    it('APEX L2 - Message with UTF8 (Japanese)', function () {
        let message = '員ちぞど移点お告周ひょ球独狙チウソノ法保断フヒシハ東5広みぶめい質創ごぴ採8踊表述因仁らトつ。';
        let signature = ApexAuthorizationUtil.getApexL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal("J1rPZ2i7JdDXzgrQ77ToMtts8So+qw5yevrde8xO8Dib6Irqehg8uz1/0RPkwdniR7HbZQbhFM26Ps038qZ80IoEJvNZEuU3EnSJaIZGBK/0/RjLZFWX0o7HGv4sBh8MQMXtoPIDu8D8GQKlUNnOM0r2sd/T6DbqVv7L53VFpTRBOG9p7tSbkE+TZiMmYFiQFWt0NhAxpTOCsEA75LQvRHws3qlNofZ4expLBdGvhFJpxe01Hx14LMgRPA+m/ohjfFcSyENs6WDTDmOm0oRjIePKVFsKbg9xd9FPUIxs5YBTkGvLopiuE/DgILL1hvBmvSzLCizGbEqyAfg6DgTg/Q==");
    });

    it('APEX L2 - Message with UTF8 (Korean)', function () {
        let message = '대통령은 즉시 이를 공포하여야 한다, 그 자율적 활동과 발전을 보장한다.';
        let signature = ApexAuthorizationUtil.getApexL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal("ornQ5HrBiKzcHdtxC4403I5U8Ns3LpIFz3ILkem0KqOHdGlr6/UhdUbtMj+3r9tgSK08bFlIpULLm6MwfxMcopX4JReYRERVvUq2FyPyYXSeUOwph16wHb3pNWiK5rIbS5w1SGonbCSFR8ZhFTeLxDUEJQAO81/UR6Hj53rVRhYvmH6UcuLJbcuItzAx9yZce4BT4/XHEdMgSZdeA8XoRwUpBWRGPNfUD/Dp+pVyIlnHokQ6hU/krYlxesIjRgdmtImhj9eCY/srr+9bKKR20tz/nVRhq2qLEzNqHCBGSArF9LNEFMlcw7BY3CoicYbqirmSRYmAOvneyxyfoQbOEg==");
    });

    it('APEX L2 - Message with UTF8 (Greek)', function () {
        let message = 'Λορεμ ιπσθμ δολορ σιτ αμετ, τατιον ινιμιcθσ τε ηασ, ιν εαμ μοδο ποσσιμ ινvιδθντ.';
        let signature = ApexAuthorizationUtil.getApexL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal("34ZlIvQhUoQuWTaG/ELU4d9T7ILE4xciQ/VuIDtBAIB+o7hCx2QXb+gQpVodKyANIDNPzxsl+2Ow6J92wtGv80o7KZli2YFuNRazgY5+2KwGai6gMQZkwGPciM3HxCXZ0rMnvUlOrSEFubUSy2Ozzl/x4csyuqUpyMKS1hIoNcxE95nHpPhPQ4vzbm6ye31y+g/Kl2i2TcQzsPXnZgMhSh8lsewneEwYw0jAyiQRSqPzsV8R6DqqJQ4UuIVmKOEOwStL7ExJHQGtDzWRF+pdCF8NyOdEjq04jEtm/1kxvVq3CI8HWyxkIicLxcdJmbf50J7bWL6Yhln1HXk5vBD0hw==");
    });

    it('APEX L2 - Extended 01', function () {
        let testBaseString = "GET&https://loadtest-pvt.api.lab/api/v1/rest/level2/in-in/&apex_l2_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l2_ig_nonce=7798278298637796436&apex_l2_ig_signature_method=SHA256withRSA&apex_l2_ig_timestamp=1502163142423&apex_l2_ig_version=1.0";
        let testExpectedSignature = "H9GB2yv1+jIbeJQ2lpX54CVNltS0ye03v2mQc0bUayRXkZj+hlK4dPjlzcfzpzoeMVxVOt7k6sHUzzdl+svWrMJ0kQW7MY4steDCRadJVAnQXzdnRFtbLmIrRUnbfI+4Gxy2zBHnCNEFCBvHRElHoe95KzjIP3TtlXt3pntUAYKsJf7IKyWz558Oach8tBIcqG9Ykl7PcBnmoppSP0ofOr47TWGArpQ22XPozRueiwmTwc7WYUc5Bdvhh1ut25ox7V6G4T0gwsO//9pwSgA1aSoJ2TRwsKuE3MgHGnP6pMvLAA7wZ0L3k/2xOHQhSRzo+goLgRTjrbVzECDg4g06pQ==";
        let signature = ApexAuthorizationUtil.getApexL2Signature(testBaseString, privateKey, passphrase);

        expect(signature).to.equal(testExpectedSignature);
    });

    it('APEX L2 - Extended 02', function () {
        let testBaseString = "GET&https://loadtest-pvt.api.lab/api/v1/rest/level2/in-in/&ap=裕廊坊 心邻坊&apex_l2_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l2_ig_nonce=7231415196459608363&apex_l2_ig_signature_method=SHA256withRSA&apex_l2_ig_timestamp=1502164219425&apex_l2_ig_version=1.0&oq=c# nunit mac&q=c# nunit mac";
        let testExpectedSignature = "LrgtqO/GRgN26wU65ugIU9IzMSyXDKMXDGFaZck135HIuOw39Ed9Tn69FrudXL+QV4S59oiYuKdqeKOK7knbk0NW3a/R9LV5tG/gYkOaNWhWz28OUniYHsnT4J4k7qH5zsQJrT42RvxBOljWQqlzjARFQcIWvdjKl7VwAslCR80KmBlsMKbuec+5QhxLRxb5Hkyr/Fp13sQJx4SxRsFqOzwCIkQvQal0mmM8E6uwrz9V8M4ozVVIa/KTqE2PzeIp45p4sqGWiuKTyNuU0fjiTN3GU43/Z03Gcth3NeJORa8kFMru9aZ3LSMNOAruuZdtK8zfnXe/To2fRhqQkNXA1g==";
        let signature = ApexAuthorizationUtil.getApexL2Signature(testBaseString, privateKey, passphrase);

        expect(signature).to.equal(testExpectedSignature);
    });
});

describe('ApexAuthorization BaseString Test', function () {
    it('APEX BaseString - Basic Test', function () {
        let url = "https://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        let expectedBaseString = 'GET&https://loadtest-pvt.api.lab/api/v1/rest/level1/in-in/&ap=裕廊坊 心邻坊&apex_l1_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l1_ig_nonce=1355584618267440511&apex_l1_ig_signature_method=HMACSHA256&apex_l1_ig_timestamp=1502175057654&apex_l1_ig_version=1.0';

        let baseString = ApexAuthorizationUtil.getBaseString(
            "Apex_L1_IG"
            , "HMACSHA256"
            , "loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ"
            , url
            , "get"
            , null
            , "1355584618267440511"
            ,"1502175057654");
        
        expect(baseString).to.equal(expectedBaseString);
    });

    it('APEX BaseString - Form Data', function () {
        let url = "https://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        let expectedBaseString = "POST&https://loadtest-pvt.api.lab/api/v1/rest/level1/in-in/&ap=裕廊坊 心邻坊&apex_l1_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l1_ig_nonce=6584351262900708156&apex_l1_ig_signature_method=HMACSHA256&apex_l1_ig_timestamp=1502184161702&apex_l1_ig_version=1.0&param1=data1";
        let  formData = { "param1": "data1" };

        let baseString = ApexAuthorizationUtil.getBaseString(
            "Apex_L1_IG"
            , "HMACSHA256"
            , "loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ"
            , url
            , "post"
            , formData
            , "6584351262900708156"
            ,"1502184161702");
        
        expect(baseString).to.equal(expectedBaseString);
    });

    it('APEX BaseString - Invalid Url 01', function () {
        var url = "ftp://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        
        expect(ApexAuthorizationUtil.getBaseString.bind(ApexAuthorizationUtil
            , "Apex_L1_IG"
            , "HMACSHA256"
            , "loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ"
            , url
            , "post"
            , null
            , "6584351262900708156"
            ,"1502184161702")).to.throw("Support http and https protocol only!");
    });    
    
    it('APEX BaseString - Invalid Url 02', function () {
        var url = "://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        
        expect(ApexAuthorizationUtil.getBaseString.bind(ApexAuthorizationUtil
            , "Apex_L1_IG"
            , "HMACSHA256"
            , "loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ"
            , url
            , "post"
            , null
            , "6584351262900708156"
            ,"1502184161702")).to.throw("Support http and https protocol only!");
    });    
});

describe('Apex Authorization Token Test', function () {
    var realm = 'http://apex.api.test/token';
    var authPrefixL1 = 'Apex_l1_ig';
    var authPrefixL2 = 'Apex_l2_ig';
    var httpMethod = 'get';
    var url = "https://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
    var appId = 'loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ';
    var secret = 'ffef0c5087f8dc24a3f122e1e2040cdeb5f72c73';
    var nonce = '-5816789581922453013';
    var timestamp = '1502199514462';

    var expectedTokenL1 = 'Apex_l1_ig realm="http://apex.api.test/token", apex_l1_ig_timestamp="1502199514462", apex_l1_ig_nonce="-5816789581922453013", apex_l1_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", apex_l1_ig_signature_method="HMACSHA256", apex_l1_ig_signature="Nw/PQAMxU9pNEfXFqd8+j4pHPKBEPqnMPLZ9LLKpD40=", apex_l1_ig_version="1.0"';
    var expectedTokenL2 = 'Apex_l2_ig realm="http://apex.api.test/token", apex_l2_ig_timestamp="1502199514462", apex_l2_ig_nonce="-5816789581922453013", apex_l2_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", apex_l2_ig_signature_method="SHA256withRSA", apex_l2_ig_signature="CH1GtfF2OYGYDAY5TH40Osez86mInZmgZETIOZCGvATBnjDcmCi6blkOlfUpGvzoccr9CA0wO8jL6VNh6cqPnVjO4bpVnSLQ8iiPOz4JK7kxJ4Cb19sX4pO6sx4srDmNqfnGOp5FeFx/rCr16ecvd3+HJF5sJEeOrDytr+HlOBf9pARVx5GroVSKxsKkXzto5XpJ2MN0Mu8eZA5BNJwune/TnnEy0oqjJWNSE+puGH4jMsp4hgLsJOwxJPS8Zg9dtPzoV60Gigxd7Yif2NqiFGI3oi0D3+sVv3QxURLPwCSE9ARyeenYhipG+6gncCR+tWEfaQBGyH9gnG6RtwZh3A==", apex_l2_ig_version="1.0"';
    var certFileName = path.join(process.cwd(), 'spec/cert/alpha.apex.gov.sg.pem');
    var passphrase = 'passwordkey';

    let liveTestToggle = true;

    it('APEX Token - Basic L1 Test', function () {
        let token = ApexAuthorizationUtil.getToken(realm, authPrefixL1, httpMethod, url, appId, secret, null, null, null, nonce, timestamp);
        expect(token).to.equal(expectedTokenL1);
    });

    it('APEX Token - Basic L2 Test', function () {
        let token = ApexAuthorizationUtil.getToken(realm, authPrefixL2, httpMethod, url, appId, null, null, passphrase, certFileName, nonce, timestamp)
        expect(token).to.equal(expectedTokenL2);
    });

    it('APEX Token - Wrong PassPhrase', function () {
        let expectedMessage = 'error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt';
        expect(ApexAuthorizationUtil.getToken.bind(ApexAuthorizationUtil, realm, authPrefixL2, httpMethod, url, appId, null, null, passphrase + 'x', certFileName, nonce, timestamp)).to.throw(expectedMessage);
    });

    it('APEX Token - Not Supported Cert Type', function () {
        let testFileName = path.join(process.cwd(), 'spec/cert/alpha.apex.gov.sg.p12');
        let expectedMessage = 'error:0906D06C:PEM routines:PEM_read_bio:no start line';
        expect(ApexAuthorizationUtil.getToken.bind(ApexAuthorizationUtil, realm, authPrefixL2, httpMethod, url, appId, null, null, passphrase, testFileName, nonce, timestamp)).to.throw(expectedMessage);        
    });    

    it('APEX Token - Invalid File Name', function () {
        let testFileName = path.join(process.cwd(), 'spec/cert/alphaX.apex.gov.sg.p12');
        let expectedMessage = 'ENOENT: no such file or directory';
        expect(ApexAuthorizationUtil.getToken.bind(ApexAuthorizationUtil, realm, authPrefixL2, httpMethod, url, appId, null, null, passphrase, testFileName, nonce, timestamp)).to.throw(expectedMessage);        
    });

    if (!liveTestToggle) {
        it('APEX Token - L0 Live Test', function (done) {
            let liveUrl = 'https://loadtest-pvt.api.lab/api/v1/rest/level0/in-in';
            let httpMethod = 'get';

            ApexAuthorizationUtil.makeHttpRequest(liveUrl, null, null, httpMethod)
            .then(function(data){ 
                expect(data.status).to.equal(200);
                done();
            })
            .catch(function(error) {
                done(JSON.stringify(error));
            });
        });

        it('APEX Token - L1 Live Test', function (done) {
            let liveUrl = 'https://loadtest-pvt.api.lab/api/v1/rest/level1/in-in';
            let token = ApexAuthorizationUtil.getToken(realm, authPrefixL1, httpMethod, liveUrl, appId, secret);
            
            ApexAuthorizationUtil.makeHttpRequest(liveUrl, token, null, httpMethod)
            .then(function(data){ 
                expect(data.status).to.equal(200);
                done();
            })
            .catch(function(error) {
                done(JSON.stringify(error));
            });
        });    

        it('APEX Token - L2 Live Test', function (done) {
            let liveUrl = 'https://loadtest-pvt.api.lab/api/v1/rest/level2/in-in';
            let token = ApexAuthorizationUtil.getToken(realm, authPrefixL2, httpMethod, liveUrl, appId, null, null, passphrase, certFileName);
            
            ApexAuthorizationUtil.makeHttpRequest(liveUrl, token, null, httpMethod)
            .then(function(data){ 
                expect(data.status).to.equal(200);
                done();
            })
            .catch(function(error) {
                done(JSON.stringify(error));
            });
        });    
    }
});
