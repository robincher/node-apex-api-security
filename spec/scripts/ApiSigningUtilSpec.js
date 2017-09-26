'use strict'
const path = require('path');
const ApiSigningUtil  = require('../../lib/ApiSigningUtil');

//ApiSigningUtil.setLogLevel('trace');
ApiSigningUtil.setLogLevel('trace');

describe('ApiSigning L1 Test', function () {
    let secret = 'secret';
    let message = 'message';
    let expectedResult = 'i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs=';
    let expectedErrMsg = 'message and secret must not be null or empty!';

    it('ApiSigning L1 - message is null or empty', function () {
        expect(ApiSigningUtil.getL1Signature.bind(ApiSigningUtil, undefined, secret)).to.throw(expectedErrMsg);
        expect(ApiSigningUtil.getL1Signature.bind(ApiSigningUtil, null, secret)).to.throw(expectedErrMsg);
        expect(ApiSigningUtil.getL1Signature.bind(ApiSigningUtil, '', secret)).to.throw(expectedErrMsg);
    });

    it('ApiSigning L1 - Secret is null or empty', function () {
        expect(ApiSigningUtil.getL1Signature.bind(ApiSigningUtil, message)).to.throw(expectedErrMsg);
        expect(ApiSigningUtil.getL1Signature.bind(ApiSigningUtil, message, null)).to.throw(expectedErrMsg);
        expect(ApiSigningUtil.getL1Signature.bind(ApiSigningUtil, message, "")).to.throw(expectedErrMsg);
    });

    it('ApiSigning L1 - Verify Signature', function () {
        let verifyResult = ApiSigningUtil.verifyL1Signature(expectedResult, secret, message);
        expect(verifyResult).to.equal(true);
    });

    it('ApiSigning L1 - Verify Signature with wrong secret', function () {
        let result = ApiSigningUtil.verifyL1Signature(expectedResult, secret + 'x', message);
        expect(result).to.equal(false);
    });

    it('ApiSigning L1 - Verify Signature with wrong message', function () {
        let result = ApiSigningUtil.verifyL1Signature(expectedResult, secret, message + 'x');
        expect(result).to.equal(false);
    });

    it('ApiSigning L1 - Message with standard ASCII', function () {
        let message = 'Lorem ipsum dolor sit amet, vel nihil senserit ei. Ne quo erat feugait disputationi.';
        let result = ApiSigningUtil.getL1Signature(message, secret);
        expect(result).to.equal("cL3lY5/rhmkxMw/dCHCa4b9Lpp/soPPACnIxtQwRQI8=");
    });

    it('ApiSigning L1 - Message with UTF8 (Chinese Traditional)', function () {
        let message = '道続万汁国圭絶題手事足物目族月会済。';
        let result = ApiSigningUtil.getL1Signature(message, secret);
        expect(result).to.equal("wOHv68zuoiIjfJHW0hZcOk4lORyiAL/IGK8WSkBUnuk=");
    });

    it('ApiSigning L1 - Message with UTF8 (Japanese)', function () {
        let message = '員ちぞど移点お告周ひょ球独狙チウソノ法保断フヒシハ東5広みぶめい質創ごぴ採8踊表述因仁らトつ。';
        let result = ApiSigningUtil.getL1Signature(message, secret);
        expect(result).to.equal("L0ft4O8R2hxpupJVkLbgQpW0+HRw3KDgNUNf9DAEY7Y=");
    });

    it('ApiSigning L1 - Message with UTF8 (Korean)', function () {
        let message = '대통령은 즉시 이를 공포하여야 한다, 그 자율적 활동과 발전을 보장한다.';
        let result = ApiSigningUtil.getL1Signature(message, secret);
        expect(result).to.equal("a6qt0t/nQ3GQFAEVTH+LMvEi0D41ZaKqC7LWJcVmHlE=");
    });

    it('ApiSigning L1 - Message with UTF8 (Greek)', function () {
        let message = 'Λορεμ ιπσθμ δολορ σιτ αμετ, τατιον ινιμιcθσ τε ηασ, ιν εαμ μοδο ποσσιμ ινvιδθντ.';
        let result = ApiSigningUtil.getL1Signature(message, secret);
        expect(result).to.equal("WUGjbeO8Jy8Rvs5tD2biLHPR0+qtAmXeZKqX6acYL/4=");
    });
});


describe('ApiSigning L2 Test', function () {
    let pemFileName = 'spec/cert/ssc.alpha.example.com.pem';
    let alphaFileName = 'spec/cert/ssc.alpha.example.com.cer';
    let betaFileName = 'spec/cert/ssc.beta.example.com.cer';
    let privateKey = ApiSigningUtil.getPrivateKeyFromPem(path.join(process.cwd(), pemFileName));
    let publicKey = ApiSigningUtil.getPublicKeyFromCer(path.join(process.cwd(), alphaFileName));
    let passphrase = 'passwordpem';
    
    let expectedSignature = "Oah2QMmy6lFh5HnMXfsao59w695L9GGJZGaBKRUacmNsUNW+jHQ6YEPEThYyGKcQ1Lj0dP+itzL5h4ZsRy4829x5nLrl2nzNNEIxEQyWfFMzfRkMO6JLCnde+yJzfR+e1i9sCvHLKyPzCjrABoTPEJiCRtfTUXuT8/4MNq1daYbAx3+iJz/hmJScIDMS580BL+A1DW4VDc260SbBPFtrqrxLKBpdZQR9/+p0Ja/6IcwjMcA/taMAt1kx/16vi9mIfjXpEVrESM6rgy6pFHXuT0kzw8XdBIewMInK10ds0ZrpsIuMW3tBwUaCKQi/O4ZDobmSOi5MnH+ZfzA7OD2/hhhy2ZoDquciOg15VMIzYWeF5P+IBWp6oB9cuji5db7mzro0FmwVV0qflYDPTUANNEIe6hGC03WDGgVsIgTjQ6WLVNuhgFIxdUdE1cqIlwBhwBJn8Wi40d4fzKNU8GFOh2GXqJ3bLVrZn6phEE0fpCM6EVk+ERzT8ipopGaS0vgE00u7sKUdgACIa342NVblXhpBJ/3TIdgbrBiRlvrXcjZj4LyZs5w3hDv2qR/170Oe/xrgyzr36usl6U6etoq2DmusjZcKukPFS3yd8CFKiyYxPmVsSbcksoge5ugRyApxnVdi63mlmK3NLT5MXB/dOpmEGYPwhhxbDuGpRmSAORI=";
    let message = 'Lorem ipsum dolor sit amet, vel nihil senserit ei. Ne quo erat feugait disputationi.';
    let expectedGetErrMsg = 'message and privateKey must not be null or empty!';
    let expectedVerifyErrMsg = 'message and publicKey must not be null or empty!';

    it('ApiSigning L2 - Message is null or empty', function () {
        expect(ApiSigningUtil.getL2Signature.bind(ApiSigningUtil, undefined, privateKey)).to.throw(expectedGetErrMsg);
        expect(ApiSigningUtil.getL2Signature.bind(ApiSigningUtil, null, privateKey)).to.throw(expectedGetErrMsg);
        expect(ApiSigningUtil.getL2Signature.bind(ApiSigningUtil, '', privateKey)).to.throw(expectedGetErrMsg);
    });

    it('ApiSigning L2 - PrivateKey is null or undefined', function () {
        expect(ApiSigningUtil.getL2Signature.bind(ApiSigningUtil, message)).to.throw(expectedGetErrMsg);
        expect(ApiSigningUtil.getL2Signature.bind(ApiSigningUtil, message, null)).to.throw(expectedGetErrMsg);
    });

    it('ApiSigning L2 - Verify Signature', function () {
        let verifyResult = ApiSigningUtil.verifyL2Signature(expectedSignature, publicKey, message);
        expect(verifyResult).to.equal(true);
    });

    it('ApiSigning L2 - Verify Signature with null PublicKey', function () {
        expect(ApiSigningUtil.verifyL2Signature.bind(ApiSigningUtil, expectedSignature, null, message)).to.throw(expectedVerifyErrMsg);
    });

    it('ApiSigning L2 - Verify Signature with null message', function () {
        expect(ApiSigningUtil.verifyL2Signature.bind(ApiSigningUtil, expectedSignature, publicKey, null)).to.throw(expectedVerifyErrMsg);
        expect(ApiSigningUtil.verifyL2Signature.bind(ApiSigningUtil, expectedSignature, publicKey, '')).to.throw(expectedVerifyErrMsg);
    });

    it('ApiSigning L2 - Verify Signature with wrong cert', function () {
        let wrongPublicKey = ApiSigningUtil.getPublicKeyFromCer(path.join(process.cwd(), betaFileName));
        let verifyResult = ApiSigningUtil.verifyL2Signature(expectedSignature, wrongPublicKey, message);
        expect(verifyResult).to.equal(false);
    });

    it('ApiSigning L2 - Verify Signature with wrong message', function () {
        let verifyResult = ApiSigningUtil.verifyL2Signature(expectedSignature, publicKey, message + 'x');
        expect(verifyResult).to.equal(false);
    });

    it('ApiSigning L2 - Message with standard ASCII', function () {
        let signature = ApiSigningUtil.getL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal(expectedSignature);
    });

    it('ApiSigning L2 - Message with UTF8 (Chinese Traditional)', function () {
        let message = '道続万汁国圭絶題手事足物目族月会済。';
        let signature = ApiSigningUtil.getL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal("f5W14LFCYjbU74FBEJ1nloJ9TD0p3QxHa1Ves8nUJgxaMs4LZOzHWYK6g+3bYp0za7GMmgV8NVP6TdiNMDCy9uFAWi8GeNGbX8JFAfSAlgKfh973RUWrvTBpwq5eq/bRRERM8Nw95ZgoEWtBJnoLzAmOxk6TDZhO+qugMXExX/I3RLZxu5oA/2jk4Pi4yWoSV+OpV/HPE2w3H0DnFKf/cxz3zAj2iNtjt4NMeGgatLuIo9SJhxRUbux8XNF8oYCbta1u57sDL/JLZzTG2eEIQ/AOmlsxGI3r7BKi198GihDqoNvZyXSmE/vBbZZkf8cruUfSx8fVTQhQcxGcPLbd52UvT45RTHc+J5ZIf93Kx9sjM+Cb/g0MdZ/Wlv5tRMKVD3StHsGwLZWaXP0ETfY4+gNgkTWtJPj+udWwPD6gYS9r9cyC6gA/VSby0hEsR6UXFqgItWnj/k7G/wLwFJMCZWiHbf9uN28Sp+x3hiDW1WIubeRq32OshqpY+4OS9QsLCQfeayOseOMnb4/2HHovLC6j7Ej+Y47493lgXy/XcE6oGM4MocToR+E4z8pR2qSzmbgsobl5FPZMggbKLHCPw4hVL1w12t68Km9Qm/nt7JisKfDH6eLV6h1MHIz2Ed0d1L2Vn21YNPgLrzMsyYXSQ2dm2MbRqvFUQE6sVAmUhYg=");
    });

    it('ApiSigning L2 - Message with UTF8 (Japanese)', function () {
        let message = '員ちぞど移点お告周ひょ球独狙チウソノ法保断フヒシハ東5広みぶめい質創ごぴ採8踊表述因仁らトつ。';
        let signature = ApiSigningUtil.getL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal("JXf2eoeADddHTnpvzjtnQl0UjQG9hVmnTLp3nuAy+vbz7FfP3jVEeOtadvlqnnf+j+SlIC1ISgHl1uGoNRzFnqwesvQPBbyUY4T66BKKlKF2HMk+6Kuz1MQnuqnTIOzooKbiWaN9ya3+lf3iDvlpiHmBcmSP02uIIx441OOYO6upWk1VmN9ZrDKaq1ynNyeGlXFs6EPjtWtfV0CPmZTb54i889/55pgg/2C83xZdFDz7pa+pqLfyNIw5z4XI7awwvcFANgU5LLzBR5eLpD08w578pXPxDuJHidWdjWw+4Pkm+xTqETr1TM5ruRDfTh7/UunG6NlH648V73Dn40sLzMpk3ujujxRFvcSM7kyn2nO3l0m3H+ZZVM8OFtzlAfhVvVWXpDF5vxEd8/Qe2bJk030MmkwwIw7EFJeexdMRbFKPYfyQEILpAiaPURTjwHWqyAuICo7+sreRI2gFRFbxsre8i74GS2BUMkmzaPzxSj/3pYhZNWvsg5ER5tbD2b8Tovq86SpEQAUOR+7oXUKnd6jswdfCrz2gibGsXOYurFom/hYqT0Jyw40jHoz+uGaDCaSVThmfS0uB302nGAF0OaotrUtELMamWK9H9hAnFOAUJpQPOojI1NT6vv35Rp+LoiS2pJck0/k6dVKoPlNS6D9OTxzpFErce/lRPS+u6js=");
    });

    it('ApiSigning L2 - Message with UTF8 (Korean)', function () {
        let message = '대통령은 즉시 이를 공포하여야 한다, 그 자율적 활동과 발전을 보장한다.';
        let signature = ApiSigningUtil.getL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal("kA5CW4eO1D7qqNy8uUglOv/Zxx4LwuwYf1Wit972nEF/Dtqd+oBzqF2Ok79bQRzKYkMo8ND6WsUq1e2DUNbx1faa5PTAvxegQqZjFdCpDKvIkcrxzLJUcLIjhQvQa2KD1F8OHuu/vVe8S/BgGLEnB7JdBdKqocHmqowzwQnIcVvAmjYWOYEe34ru3WlLLuAok8JYMxt68gSI72f2jwtNIQX88/CFdvh/UpsDGpS15I0Bx+OgFe70Wd9c/YO3KX88HB5MBUibLkQmnFBBiWrJhp5fthBnPY2IxIy47Lncnih64a0iUgCO/hpss1FEq3bo6uvXqbfSPxCdqrnXRtQojSxlfF/0Knu8dyZYMV9DvhL7AxcHZzlIaB2Zd9DhVvKZN47qgGzNm0m64hLwxqMGje1pN/ScfnmHWs1hJYOgpUs96Au+93Mig877Gt9BXmSHL09rQOMrAKZ5ec+8Jdo7YQB2P3fi80aZ3ZLrdZCkiRXsBmT+ZCrt8VJ8QM+vyDe2fGuZqvC9hfhHbKe87tPwTfrsaKKWpb5sHAGXVoPgmOi8BtzdwtVlaFVpJQrZQ5VTt45qMaEx/nj++QrpkaWkXQa2DcF+I1+klTsOzGAnONGkQ2CI/HgHJaYyMFTKTnNVtULWvue93b/AGK4ViV8Q3rI7p3ZVSjd+DNOH9SnLCAI=");
    });

    it('ApiSigning L2 - Message with UTF8 (Greek)', function () {
        let message = 'Λορεμ ιπσθμ δολορ σιτ αμετ, τατιον ινιμιcθσ τε ηασ, ιν εαμ μοδο ποσσιμ ινvιδθντ.';
        let signature = ApiSigningUtil.getL2Signature(message, privateKey, passphrase);
        expect(signature).to.equal("gU++Nk2yz3n0X+ezZ6KfJ8CmT8RM+OTKEQ/UE+FaCoszAv5FvNDdTpYaxsHRofFEsbZYjo15xqVoutYbUMz4MyD5egTiz24GSyWEwo+d/3QvUXvgjGZO13Gdf4UVCYUURMEBbQOuOet0JkzybDDgOvzDdbDBb2tUzz7dUQacG+U+Ub/JyH6q22Uw9a2NkeXdzyzMBAcwHR8aSDcIZ3aHAUc11MB7DjdNMXVuF+DJ50wAVMrG6Z3Ha+FlVx0YRDI5LOcz3BFlFIA+n8UP4YWsu2OZPxUL7b2yz5VTCGnccqf/V3d+Deth4TX7bJTg7wzEI5Dyts533zhFK1vuW3j0GOmrXtnqRleMt2jFL47NKSIF/D8S9WeTBYYY/YsbQazv9sV+GLM2MEUY2MVrsTDjZSjUEhPYHa7eyT6HGuon+1EX4HkQOmf8uaIBbjxsUn/K+y5wUkX4fkIZYXE3AhRmyPMSgC6IyP2WLHAFvUgcgMKmSloXJLN5KyY4iygLd1kqxrvAh0eYO4fEjJV9YgpNDKwf84wNSXxSTtjUGmrzhVF7z4xnz3oEHMkul7hJKH4matTYGez1fBsbiUVeO4zmoXgfH2OeWc/y9iBGKFxixE8WpTSqLcOpQTp6ziCPsQI/+URRP+/w0gulRDNPYvL/SPlL8JVyOpbS0gDPcMZ0teM=");
    });

    it('ApiSigning L2 - Extended 01', function () {
        let testBaseString = "GET&https://example.com/api/v1/resources/&apex_l2_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l2_ig_nonce=7798278298637796436&apex_l2_ig_signature_method=SHA256withRSA&apex_l2_ig_timestamp=1502163142423&apex_l2_ig_version=1.0";
        let testExpectedSignature = "MBOIpHi90ME8YMHMgkm4KIIVmhCHPptxUqXtgvA9g0MQljgg85G+LN7f6Wc0J/CKWD/hBDlfyVqBJk5zKLxYvJfeg4TPe22ybCkyv7lvKF+EGOthgZXBHS1MLL9RqfcipyT98xdKXEUX9vDEvmV512HqBKgL/9xiJBn7GH5qWYatfnJT5H9Q/GkXENvdJ2JT005SaWjlVyOojeLlcm5pl64kczyeyuqrSD9Sub4kfUNaEkGVbtl0YVOz9tmnDGw+hvIPUCbNLPk5M7vbfDD+66ODl7Y7bFh+UmEtKZoh0Pgw4/yn/5UVVsCLd8KNGWRQ8eh3y1bk1xot49wz7GHSneo+4sot6h0RmmHw+w4u6tvnDKjd4oWWFTN+05PIu2iAbeu+w5aalMrGDJsySYbnEDhN91SKWwKC+9Nbhf/5bxFqxudhEzEitiRqMiYMVbROXXG2z/6gIAm6EhRoWroxH3fj73/T57uOXZRDtOFUwQHiwndLeQG9WAwgtoByRQ1NInVfpQuxn2MfdMXvD+cflo5WfeyC7VsGDfawCEp61akNsdc9rnU6cnud1iURL6lNEsq/DJURgoXn9uLIwIrv6PODduxpZ0++w5ZwTqvZcH7qBCfkalL3yT7E6OUyW9G/kxCDsjE3zO68jZ6lqYQQ+YlTFbqvdZ2C6CoE7TL+EWs=";
        let signature = ApiSigningUtil.getL2Signature(testBaseString, privateKey, passphrase);

        expect(signature).to.equal(testExpectedSignature);
    });

    it('ApiSigning L2 - Extended 02', function () {
        let testBaseString = "GET&https://loadtest-pvt.api.lab/api/v1/rest/level2/in-in/&ap=裕廊坊 心邻坊&apex_l2_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l2_ig_nonce=7231415196459608363&apex_l2_ig_signature_method=SHA256withRSA&apex_l2_ig_timestamp=1502164219425&apex_l2_ig_version=1.0&oq=c# nunit mac&q=c# nunit mac";
        let testExpectedSignature = "BUEfjXecS3htVfpes/D/8Y7y++nU/puiobP6IVrehprW209NrZ7GqWmQhRc1H7zGRLnEiW/H6uPIvDqUpZWB6UbJxhJLRBdNN0P04/D/KaPnDv5nScdzxhYD5Lrms+BbpeCSHLNtv8zKH1HJh+o/QchPodK8ZfzqRA1X2PRLviC44b8ER+Lo3yRWsqfNABP48abBR6gxsoezHXdA/ZlgzWdVkZXlebIfa89c2oSNRSmEO/rI5VVntxABKD1JixnrsA1PuAhREvQhEQzyanE8Y09gNaty90vXkPOoTmCv0rkq4Bhk74jxSzTt7/8wOPs96bTe0nAFllNBO0D57AKmZdZHkfGdpAIMsjpUXJp53MYljYfrlCKgkhN8d6Zs2f8h8wBHr6x8wZ7QpIhI1+fakv53rkRWGJYLebuAPY3shzynlrio2JvCeCfEV9uZ8zdi+dQjS0U3p4WbETTLE9bH2CO054f43FL2vXRjBWt6YxRN1NmnVRHn09bnzfyTaoET6nmJ6yttxbRMbeI1inR6jSEaLxpxsL2h8K5uKHRES7+rt+g1bqRnfHmTKeVjxNRnfelLfSuo2EzxXG9jOfIA8g73mRd8aswR6wDqOjwlXo9rPvasMD+ruBNkcMHJTKJ3HwicXmNfIrsKy9/vGM0xgKYFnKNPcFOmif2CDhlxaLU=";
        let signature = ApiSigningUtil.getL2Signature(testBaseString, privateKey, passphrase);

        expect(signature).to.equal(testExpectedSignature);
    });
});

describe('ApiSigning BaseString Test', function () {
    it('ApiSigning BaseString - Basic Test', function () {
        let url = "https://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        let expectedBaseString = 'GET&https://loadtest-pvt.api.lab/api/v1/rest/level1/in-in/&ap=裕廊坊 心邻坊&apex_l1_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l1_ig_nonce=1355584618267440511&apex_l1_ig_signature_method=HMACSHA256&apex_l1_ig_timestamp=1502175057654&apex_l1_ig_version=1.0';

        let baseString = ApiSigningUtil.getBaseString(
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

    it('ApiSigning BaseString - Form Data', function () {
        let url = "https://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        let expectedBaseString = "POST&https://loadtest-pvt.api.lab/api/v1/rest/level1/in-in/&ap=裕廊坊 心邻坊&apex_l1_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l1_ig_nonce=6584351262900708156&apex_l1_ig_signature_method=HMACSHA256&apex_l1_ig_timestamp=1502184161702&apex_l1_ig_version=1.0&param1=data1";
        let  formData = { "param1": "data1" };

        let baseString = ApiSigningUtil.getBaseString(
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

    it('ApiSigning BaseString - Invalid Url 01', function () {
        let url = "ftp://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        
        expect(ApiSigningUtil.getBaseString.bind(ApiSigningUtil
            , "Apex_L1_IG"
            , "HMACSHA256"
            , "loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ"
            , url
            , "post"
            , null
            , "6584351262900708156"
            ,"1502184161702")).to.throw("Support http and https protocol only!");
    });    
    
    it('ApiSigning BaseString - Invalid Url 02', function () {
        let url = "://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊";
        
        expect(ApiSigningUtil.getBaseString.bind(ApiSigningUtil
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

describe('ApiSigning Token Test', function () {
    let realm = 'https://example.com';
    let authPrefixL1 = 'Apex_l1_ig';
    let authPrefixL2 = 'Apex_l2_ig';
    let httpMethod = 'get';
    let url = "https://example.com/api/v1/resources";
    let appId = 'loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ';
    let secret = 'ffef0c5087f8dc24a3f122e1e2040cdeb5f72c73';
    let nonce = '-5816789581922453013';
    let timestamp = '1502199514462';

    let expectedTokenL1 = 'Apex_l1_ig realm="https://example.com", apex_l1_ig_timestamp="1502199514462", apex_l1_ig_nonce="-5816789581922453013", apex_l1_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", apex_l1_ig_signature_method="HMACSHA256", apex_l1_ig_signature="ua32WiJ7FfDOZKuaaVDJyF12Yq0a8leTt5KAtHcTQc0=", apex_l1_ig_version="1.0"';
    let expectedTokenL2 = 'Apex_l2_ig realm="https://example.com", apex_l2_ig_timestamp="1502199514462", apex_l2_ig_nonce="-5816789581922453013", apex_l2_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", apex_l2_ig_signature_method="SHA256withRSA", apex_l2_ig_signature="QB1k89vfJg23W4adJJa5uw/OcyRsrD+okaQx0G+ow3sfZoh3RbjcuwOF5Z31iR7HwEq0QDjD50np5FuICh4wNCJh/HTnYonY+Wal9PFy+fdffuR9Us5l3bct2CwvmOJFcRo033M3l2DGMbnn4W/brJ2mZuSXfQajbQSdf5hMpsKdefxw+OROVSMesADNIqXcEZxEnDC0MLxDyIzhqQfKEmW/tDPd4DWEeBE9d5hQ5ToW7FH2n0PSr36Q+Z1V2XlvMTQNjeb5AWzDbBfKgm528Bkxpi0I3QsjcpCcHafTSECn6pNNRjSAYu+iODEiZjYJfVPfvYZo1enj3vd8vZd/nAG2h/vXJliRxE1R74fWCS6XIdnkMnKEt2TcISXtB1PLcj4bbYvnDNHofMxOGSB/cnJoWPjKm0KT58RygNXnvDaNT+IeAO6cplkXS/S+zeqwh7LsuwBUtHR0ikUkblL+SqUbV/RdLbgr//wF7K9wxOaTsCVt0vLERfs1JmoFCjzzV05giHkWWf9lt2ssqhww/BD83Nc4mmmocWeM9q8wT1t/oaItBOFwmlRxxKv2HMOv1yR9Z+J3Qoos3S3/bHjXJyDIqGeHzDS7fARmS7wGGA4VA4Yazo8EBhsOzz3uHs0bQQHi3Qc/1PeKshujaVGUaimZXTwJrf3oIefXzkSExPw=", apex_l2_ig_version="1.0"';
    let certFileName = path.join(process.cwd(), 'spec/cert/ssc.alpha.example.com.pem');
    let passphrase = 'passwordpem';

    let liveTestToggle = true;

    it('Api Signed Token - Basic L1 Test', function () {
        let token = ApiSigningUtil.getToken(realm, authPrefixL1, httpMethod, url, appId, secret, null, null, null, nonce, timestamp);
        expect(token).to.equal(expectedTokenL1);
    });

    it('Api Signed Token - Basic L2 Test', function () {
        let token = ApiSigningUtil.getToken(realm, authPrefixL2, httpMethod, url, appId, null, null, passphrase, certFileName, nonce, timestamp)
        expect(token).to.equal(expectedTokenL2);
    });

    it('Api Signed Token - Wrong PassPhrase', function () {
        let expectedMessage = 'error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt';
        expect(ApiSigningUtil.getToken.bind(ApiSigningUtil, realm, authPrefixL2, httpMethod, url, appId, null, null, passphrase + 'x', certFileName, nonce, timestamp)).to.throw(expectedMessage);
    });

    it('Api Signed Token - Not Supported Cert Type', function () {
        let testFileName = path.join(process.cwd(), 'spec/cert/ssc.alpha.example.com.p12');
        let expectedMessage = 'error:0906D06C:PEM routines:PEM_read_bio:no start line';
        expect(ApiSigningUtil.getToken.bind(ApiSigningUtil, realm, authPrefixL2, httpMethod, url, appId, null, null, passphrase, testFileName, nonce, timestamp)).to.throw(expectedMessage);        
    });    

    it('Api Signed Token - Invalid File Name', function () {
        let testFileName = path.join(process.cwd(), 'spec/cert/alphaX.apex.gov.sg.p12');
        let expectedMessage = 'ENOENT: no such file or directory';
        expect(ApiSigningUtil.getToken.bind(ApiSigningUtil, realm, authPrefixL2, httpMethod, url, appId, null, null, passphrase, testFileName, nonce, timestamp)).to.throw(expectedMessage);        
    });

    if (!liveTestToggle) {
        it('Api Signed Token - L0 Live Test', function (done) {
            let liveUrl = 'https://example.com/api/v1/resource';
            let httpMethod = 'get';

            ApiSigningUtil.makeHttpRequest(liveUrl, null, null, httpMethod)
            .then(function(data){ 
                expect(data.status).to.equal(200);
                done();
            })
            .catch(function(error) {
                done(JSON.stringify(error));
            });
        });

        it('Api Signed Token - L1 Live Test', function (done) {
            let liveUrl = 'https://example.com/api/v1/resource';
            let token = ApiSigningUtil.getToken(realm, authPrefixL1, httpMethod, liveUrl, appId, secret);
            
            ApiSigningUtil.makeHttpRequest(liveUrl, token, null, httpMethod)
            .then(function(data){ 
                expect(data.status).to.equal(200);
                done();
            })
            .catch(function(error) {
                done(JSON.stringify(error));
            });
        });    

        it('Api Signed Token - L2 Live Test', function (done) {
            let liveUrl = 'https://example.com/api/v1/resource';
            let token = ApiSigningUtil.getToken(realm, authPrefixL2, httpMethod, liveUrl, appId, null, null, passphrase, certFileName);
            
            ApiSigningUtil.makeHttpRequest(liveUrl, token, null, httpMethod)
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
