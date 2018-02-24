'use strict';
const path = require('path');
const ApiSigningUtil = require('../../lib/ApiSigningUtil');

ApiSigningUtil.setLogLevel('trace');

describe('ApiSigning L1 HMACSHA256 Signature Test', function () {
    let secret = 'secret';
    let message = 'message';
    let expectedResult = 'i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs=';
    let expectedErrMsg = 'message and secret must not be null or empty!';

    it('ApiSigning L1 HMACSHA256 - message is null or empty', function () {
        expect(ApiSigningUtil.getHMACSignature.bind(ApiSigningUtil, undefined,
            secret)).to.throw(expectedErrMsg);
        expect(
            ApiSigningUtil.getHMACSignature.bind(ApiSigningUtil, null, secret)).
            to.
            throw(expectedErrMsg);
        expect(
            ApiSigningUtil.getHMACSignature.bind(ApiSigningUtil, '', secret)).
            to.
            throw(expectedErrMsg);
    });

    it('ApiSigning L1 HMACSHA256 - Secret is null or empty', function () {
        expect(ApiSigningUtil.getHMACSignature.bind(ApiSigningUtil, message)).
            to.
            throw(expectedErrMsg);
        expect(
            ApiSigningUtil.getHMACSignature.bind(ApiSigningUtil, message,
                null)).
            to.
            throw(expectedErrMsg);
        expect(
            ApiSigningUtil.getHMACSignature.bind(ApiSigningUtil, message, '')).
            to.
            throw(expectedErrMsg);
    });

    it('ApiSigning L1 HMACSHA256 - Verify Signature', function () {
        let verifyResult = ApiSigningUtil.verifyHMACSignature(expectedResult,
            secret, message);
        expect(verifyResult).to.equal(true);
    });

    it('ApiSigning L1 HMACSHA256 - Verify Signature with wrong secret',
        function () {
            let result = ApiSigningUtil.verifyHMACSignature(
                expectedResult, secret +
                'x', message);
            expect(result).to.equal(false);
        });

    it('ApiSigning L1 HMACSHA256 - Verify Signature with wrong message',
        function () {
            let result = ApiSigningUtil.verifyHMACSignature(expectedResult,
                secret, message + 'x');
            expect(result).to.equal(false);
        });

    it('ApiSigning L1 HMACSHA256 - Message with standard ASCII', function () {
        let message = 'Lorem ipsum dolor sit amet, vel nihil senserit ei. Ne quo erat feugait disputationi.';
        let result = ApiSigningUtil.getHMACSignature(message, secret);
        expect(result).to.equal('cL3lY5/rhmkxMw/dCHCa4b9Lpp/soPPACnIxtQwRQI8=');
    });

    it('ApiSigning L1 HMACSHA256 - Message with UTF8 (Chinese Traditional)',
        function () {
            let message = '道続万汁国圭絶題手事足物目族月会済。';
            let result = ApiSigningUtil.getHMACSignature(message, secret);
            expect(result).
                to.
                equal('wOHv68zuoiIjfJHW0hZcOk4lORyiAL/IGK8WSkBUnuk=');
        });

    it('ApiSigning L1 HMACSHA256 - Message with UTF8 (Japanese)', function () {
        let message = '員ちぞど移点お告周ひょ球独狙チウソノ法保断フヒシハ東5広みぶめい質創ごぴ採8踊表述因仁らトつ。';
        let result = ApiSigningUtil.getHMACSignature(message, secret);
        expect(result).to.equal('L0ft4O8R2hxpupJVkLbgQpW0+HRw3KDgNUNf9DAEY7Y=');
    });

    it('ApiSigning L1 HMACSHA256 - Message with UTF8 (Korean)', function () {
        let message = '대통령은 즉시 이를 공포하여야 한다, 그 자율적 활동과 발전을 보장한다.';
        let result = ApiSigningUtil.getHMACSignature(message, secret);
        expect(result).to.equal('a6qt0t/nQ3GQFAEVTH+LMvEi0D41ZaKqC7LWJcVmHlE=');
    });

    it('ApiSigning L1 HMACSHA256 - Message with UTF8 (Greek)', function () {
        let message = 'Λορεμ ιπσθμ δολορ σιτ αμετ, τατιον ινιμιcθσ τε ηασ, ιν εαμ μοδο ποσσιμ ινvιδθντ.';
        let result = ApiSigningUtil.getHMACSignature(message, secret);
        expect(result).to.equal('WUGjbeO8Jy8Rvs5tD2biLHPR0+qtAmXeZKqX6acYL/4=');
    });
});


describe('ApiSigning L2 RSA256 Signature Test', function () {
    let pemFileName = 'spec/cert/ssc.alpha.example.com.pem';
    let alphaFileName = 'spec/cert/ssc.alpha.example.com.cer';
    let betaFileName = 'spec/cert/ssc.beta.example.com.cer';
    let privateKey = ApiSigningUtil.getPrivateKeyFromPem(
        path.join(process.cwd(), pemFileName));
    let publicKey = ApiSigningUtil.getPublicKeyFromCer(
        path.join(process.cwd(), alphaFileName));
    let passphrase = 'passwordpem';

    let expectedSignature = 'OsOqG/6hJfGmpCDkqBSZ4netNJDex1lzBYTzGjvjShSFEhJEzAD1zNHKg8Zf9Dve7o9lx3+Yrhrn68nMocgUSOvinhUNF3ttLWw36GzXG7BFJRSIbeUfY3C1vAhkjxmE8oiYoIWctT9qBOL/3GY5QD1H3DiWrb3OLUjy52dsAPmK2P5ofdo8Erd5/0mTxgX+OLMADLJUXq/Aajp1ZIF+djQipPHg0Ms1sNkSHCURxyCjRMKOHNe8DH15lKcApBBjd3XPlb+PGlFl/ffc5Q1ALnAOmsqN6hi8mW+R6Eb0QZsvoRMFSA7kQdWvkCrlWtP5ux+A2Ji/b48SWFSJurVz7yRBhJFDYlvTTCGcgLfwn3TJXa/YbCK05qy307i6X9jnfYaqSYhKC61ExTZYE2SyfagAcWVlSlq3bEovZXllKAwq8Yqyez2EqkOoSzJdj5gmJ1Pb4wN/ss7yYybRSvFShQunj/t6TiQDCJuhghXOfV5Scs/wqjDMWViqrA65YOQHROqAku81NiWFmciVHjk6bNAGsp7iE0p5XnA4z9B41ZVPsxsSXUg4tZvpUrZSpNzlGFBi/uEa1UYcrUd8APzBCvUa75RhZsfxRsCOkpyOEmqoFzg4ngCfegJzBpU5La9e0SOlRvW29p9CK7fS/FZC5YJtP1kucaBN5pX/mxaYeUQ=';
    let message = 'Lorem ipsum dolor sit amet, vel nihil senserit ei. Ne quo erat feugait disputationi.';
    let expectedGetErrMsg = 'message and privateKey must not be null or empty!';
    let expectedVerifyErrMsg = 'message and publicKey must not be null or empty!';

    it('ApiSigning L2 RSA256 - Message is null or empty', function () {
        expect(ApiSigningUtil.getRSASignature.bind(ApiSigningUtil, undefined,
            privateKey)).to.throw(expectedGetErrMsg);
        expect(ApiSigningUtil.getRSASignature.bind(ApiSigningUtil, null,
            privateKey)).to.throw(expectedGetErrMsg);
        expect(
            ApiSigningUtil.getRSASignature.bind(ApiSigningUtil, '',
                privateKey)).
            to.
            throw(expectedGetErrMsg);
    });

    it('ApiSigning L2 RSA256 - PrivateKey is null or undefined', function () {
        expect(ApiSigningUtil.getRSASignature.bind(ApiSigningUtil, message)).
            to.
            throw(expectedGetErrMsg);
        expect(
            ApiSigningUtil.getRSASignature.bind(ApiSigningUtil, message, null)).
            to.
            throw(expectedGetErrMsg);
    });

    it('ApiSigning L2 RSA256 - Verify Signature', function () {
        let verifyResult = ApiSigningUtil.verifyRSASignature(expectedSignature,
            publicKey, message);
        expect(verifyResult).to.equal(true);
    });

    it('ApiSigning L2 RSA256 - Verify Signature with null PublicKey',
        function () {
            expect(ApiSigningUtil.verifyRSASignature.bind(ApiSigningUtil,
                expectedSignature, null, message)).
                to.
                throw(expectedVerifyErrMsg);
        });

    it('ApiSigning L2 RSA256 - Verify Signature with null message',
        function () {
            expect(ApiSigningUtil.verifyRSASignature.bind(ApiSigningUtil,
                expectedSignature, publicKey, null)).
                to.
                throw(expectedVerifyErrMsg);
            expect(ApiSigningUtil.verifyRSASignature.bind(ApiSigningUtil,
                expectedSignature, publicKey, '')).
                to.
                throw(expectedVerifyErrMsg);
        });

    it('ApiSigning L2 RSA256 - Verify Signature with wrong cert', function () {
        let wrongPublicKey = ApiSigningUtil.getPublicKeyFromCer(
            path.join(process.cwd(), betaFileName));
        let verifyResult = ApiSigningUtil.verifyRSASignature(expectedSignature,
            wrongPublicKey, message);
        expect(verifyResult).to.equal(false);
    });

    it('ApiSigning L2 RSA256 - Verify Signature with wrong message',
        function () {
            let verifyResult = ApiSigningUtil.verifyRSASignature(
                expectedSignature,
                publicKey, message + 'x');
            expect(verifyResult).to.equal(false);
        });

    it('ApiSigning L2 RSA256 - Message with standard ASCII', function () {
        let signature = ApiSigningUtil.getRSASignature(message, privateKey,
            passphrase);
        expect(signature).to.equal(expectedSignature);
    });

    it('ApiSigning L2 RSA256 - Message with UTF8 (Chinese Traditional)',
        function () {
            let message = '道続万汁国圭絶題手事足物目族月会済。';
            let signature = ApiSigningUtil.getRSASignature(message, privateKey,
                passphrase);
            expect(signature).
                to.
                equal(
                    'BcgiwVRV5NPf2D15NMA7PjfheHY+jYeODlODuaAahd5dU/fuGanMcFpFuKJtxuCQLOE3veZMCC7V+hb/LEaBfkvXw+7gl8WtLu+T927Xs+3517AZm9vZ3nU34FIMAQpTJ8QbciFcd5FAybDiMuCfzvVE59yTSL/JmzSH4188/K6Z1uZ29VizrC2BwtVA/SHaWN1SMUGX6u0tQN5nE4dGZ9lRKm1Jd2rsUNDmqsmUZDJTbgoZbTJjNQklRv48GunXYBt/cfi9T5bryIVilqUphTIe6GrjLXZ1NVVCcMCJaCzAesX2dWUwLCEULcM4Vqw+7SWN20k4zcori5+QkwNH/eyViHwKiYY+neIusUU4HcafIXNHlYQjj1OVEXqPn2P7TzH9y+7TXheNrQ03P6NnRBjEW/bAgoCplbhYWnlNtu+BBNLn9+6rN/ePJz265Wetb16ZjG+ZwbV72PUkGxeFoT7cGBNvcC5zK4bFZV4AOr7TqE9Nt/xm9Xi7/gM0oU7zgYm+32LJaAxG2vax9EFdi3yBKrGRBYLaMH/6KEreZV+iZgLsqK/7tWEQom843iTmeRaxA4/Xeg3MLPyyxrWtQBqu2O/lv6pEf+scnc2Mg6gyc5uRm0luxJUBkqI6i/BAHGZRN1cDkMhWywAcWs3yxxV6qptFYxl6ubLCbCXtiw0=');
        });

    it('ApiSigning L2 RSA256 - Message with UTF8 (Japanese)', function () {
        let message = '員ちぞど移点お告周ひょ球独狙チウソノ法保断フヒシハ東5広みぶめい質創ごぴ採8踊表述因仁らトつ。';
        let signature = ApiSigningUtil.getRSASignature(message, privateKey,
            passphrase);
        expect(signature).
            to.
            equal(
                'RtNtUoRXhNFrFPMy5aJjPTB8yI9AyvLqIKmgjmarxZhB/aOLXSJtHHJMgufOLDsUzEyDenlPuRp4ju2Dp870P19H/IxLktTqkU3DZU35tqk21TWNQDmdl/P9YjY3BNJqU4YBV3A83KRDRhJh235Hjy20dbJqZAe/oL/8GboRd0W941Oj2VfC53SmVAYWQV1aJb4qV3cvoQG2OtcBMNA+ayG+0oTB9AtGZ3CqCUPqbfbb36oc81jYQj0nElHRew7QdclfpAUQaDgCF6svduji2rdXrU+fRYaiRPtm4F1zv9JVuIjKOZRqVQeQ3Nb/X8zUMEBNeWToQPmzoHz6hAEfzYUif2IJ1KqYooV29AwOvwu1itAeUwLtqlHK3QGJYaJVrw05EyAg1IsicAQ+szP+6t6Er3GjhRSXwIcpKdxLUHVtwFoK7E1L4FqxCW+Pokm97h0/rqWREt7DJvoIofQ8rtfEfao5CTaJOQyMRUx+Ds1Kytzpzd1T7aWFvdzFxo9YLfsZ/DzIy2F7iMi9c1b8WYfStlBvfUeEEeByZj+7FrvLMo9Ys5K/UweBfTcBHdPfCmW5RTJhmfK0p+EVsntLqkCbWMoQ6JdNZoASSB7E+NPGJuk3kuVo4sPnPy9vQlHsYJWktXjwTmBp4EZzfcia6U5TSWG0Wdn4ohCYQU2Y/sg=');
    });

    it('ApiSigning L2 RSA256 - Message with UTF8 (Korean)', function () {
        let message = '대통령은 즉시 이를 공포하여야 한다, 그 자율적 활동과 발전을 보장한다.';
        let signature = ApiSigningUtil.getRSASignature(message, privateKey,
            passphrase);
        expect(signature).
            to.
            equal(
                'GW0UWsS/bdP22Zd8D+WCZtz4LhyHF/8QemS7xTDPzhSlN+yjPtu7O0f/GGl3s+U1Cm3gUjMIRKbSKyi441Z57MD/9Ju8swtAJkHh9K/LPf/fFfm3UMN0EU7jeoEUkFG3AM8rR24ih16HFpK8RcDHDRL5+tAoU6au/JRLAnuRnhcOjunSC91OhTZJqSGYukoarLYVFxnLFyZPviZPe+aaFW4ZUrD+Kc6K2C/htHS1S/7NJedDsD8If31+dh/wdkIbvhQRDgWBJlSAoqOqmeFSRIIXW/VeufOjXZ9fxa/pmsBDN5BB5Fb3MguxebD61c0MN4F+gnRQ/5arKQL5oIn/QAGan6Ll7s7nUGpa88sdVKRqw/TVcqmYeIFgWBUhnk2p54tvWbCXski63z4QRC+4TZ/ITPgn1sDqsD5Qf9/Ly1RPpJPODNgIYb5i6vh94gchqrF1g3EphbJ3riWCqREoBuCD+yqS2DSE7QWg1gjaHtT8kzcxkt3KpJoLPlZPKt92y03/av8a0AXpc2H7pw2mJ4i13xDsiRKavE4R7pwrfUJxSxYD2jBPZgNTo3XxaboHZgFbvyyw3xHreSo9CmM0mL94qha4jv2TqGuURooiBfizxzuHeMub1t8VIAXOiTk/iQtBPvGLtsQzFW3TeAeZtiYSGBeKOmb6O1vtetBurQk=');
    });

    it('ApiSigning L2 RSA256 - Message with UTF8 (Greek)', function () {
        let message = 'Λορεμ ιπσθμ δολορ σιτ αμετ, τατιον ινιμιcθσ τε ηασ, ιν εαμ μοδο ποσσιμ ινvιδθντ.';
        let signature = ApiSigningUtil.getRSASignature(message, privateKey,
            passphrase);
        expect(signature).
            to.
            equal(
                'G6FezmgEqrnZNxqWfIE8Rcb49L3WQRcAQxQ0xX2sibejHHiOXPXU811OIsL7hsYmyLSSoY3IXTtu271MwfR1TTiODBnIqpgZ0jwmyKK7YoHUDqRgKmVscBnwotw2ntDn1eA2BAU2yKi+UOeUbDcY8dCK/qxdoKdvQg99zjmm1P4EG0dFlmh07oa2ByH4pgioaxI0sKQdDL14qbjrKOiFtfgdv5NEd1Q3kP240p9vLOoScPsRvRZlpWGPCUa0R9wQMtXZAKB3TVs+p8hu5ZHmG9JP2Jo5FRt8EkCG6V3Fg8qlbDO5m9B49atynVBsNSQkYKpCylokJI/mcESNciliQmOwkLmqh6YeELX82PSvnErIPRSAzrqkKYed/HI5gL2Z8pCOwohSfuMeoOrba3JeD98kMQHGwhw+pxSP6lnTCxLwLREhqgSrcXfymhc2TCbA/w/1gT3MjTIDjIF1HgtT2bPpjco62iuKPyrjejb4ARGcty5mlUjbPNUCD/DB4qgghnhbtvWJFJxF7Egs/BeDk5swyyvFBrlXPd/yhCpMJRAOZ0bK3Adj1ij0tVH/kHtDzRYZnF0ZQXZBlHyP2DMvlnJQbIDrTBuojRYFb8W7CPWc/P4RQIGwRv6ZvT+LLl+uuNpvNoVFc/EB0gKII819nINmCjcmuYhsboBLkJ9XHyE=');
    });

    it('ApiSigning L2 RSA256 - Extended 01', function () {
        let testBaseString = 'GET&https://example.com/api/v1/resources/&apex_l2_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l2_ig_nonce=7798278298637796436&apex_l2_ig_signature_method=SHA256withRSA&apex_l2_ig_timestamp=1502163142423&apex_l2_ig_version=1.0';
        let testExpectedSignature = 'jDr65Syz+jL2CZdKLMSJhO/8vUj5zP5phuyBVYhTn4mTolG63fjuheJFiQH63Zg0g6sTbbf78pG1+seQzffDGZay39x6FMWJkK0lJu4uGDj0P/fGgO58GhiVGAsvn2yOGIjDZ1PjU6wUG/bzSzgTFSBYJElBwINvbglJL9GTV8OI4eRTG37vxgy1awmAgyGpCtsdThKO0WwJWG0dnJ39fOaS41ZH4xpYUHw6n7hwA0Qgae+Ezk6J/0yAZULFJfRD2H4KYvTvBz/PfvUdj4eDElCWYbno6pW0pjtxfBD4H8qk5LIZC1z6yp7ocmhISdiCSBgvH5WAtL/uJ1ZLrOobFyABbLvkEHpxLWsWYy1Btrdj6kcJOg9q4BXzzaWquhyrTEnEXPVYhorRwP9aktlXEA6pDqPWdnksOhuebzyD8LQ92pmGqh0CHyj/zBkqvGgNjfgXBNNlRO8OeXlx0Tu9pAk/u7wBxbQaTHUzC8nFq+b76zgEdkHcemAtNKYvQfbDn50gON0fFpH9X7yQkoYDv1Tk3ye1sapYLVl3h6zwBtrufp9JzT+ytDneQPzjIXHaMp2eMdj4CvQELVVx4S0jvi7Qq24IcDZS0kYE25UFZVgKL2xgrZksncxq2kzT67lwfJmLc9Q/KOihDdgoTYYC2ZUmfkkxzvjuoWqT7dbUjj8=';
        let signature = ApiSigningUtil.getRSASignature(testBaseString,
            privateKey, passphrase);

        expect(signature).to.equal(testExpectedSignature);
    });

    it('ApiSigning L2 RSA256 - Extended 02', function () {
        let testBaseString = 'GET&https://loadtest-pvt.api.lab/api/v1/rest/level2/in-in/&ap=裕廊坊 心邻坊&apex_l2_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l2_ig_nonce=7231415196459608363&apex_l2_ig_signature_method=SHA256withRSA&apex_l2_ig_timestamp=1502164219425&apex_l2_ig_version=1.0&oq=c# nunit mac&q=c# nunit mac';
        let testExpectedSignature = 'PAtGMMC5vWprJh4T1QkXiZWpqH9wA1hZz6AEjvHfEIalaejYdpDG31vb1boMjnKqoF2moydAyz97pd1s6FMHYZ3cv2YI/K3Wjf2pjcepI2nXwErncSve2W45CtzJ+TQWwqcttcfm/avhFpOYw74v/AHSrWbuoqPpVLAuznLBHwkiKJPBpt/Tdj1S/6Fmqu7OJu81OEQUBdhySVXtZMBtFHEFMviR2eDG7NcOZ2fspQUrCSdtEFKVyjMAcaFY6uxP5knRoq54FEHCmYotQ/J+VIWD3I0FL1ZswVtJ1zAM41rxpvfEvQFe9jucV6KN3kXnWD6hJbu4pXnakvcQKADgcBDvX0A9dzdhB9ibiWpKT8bXQwZDxYc6HqX9p83HikodV7x6p5Cd03Tol/9JaJqRQHe5ahwucCjnP5WqbTb4PrCNHeCGRj207ncpxBuafllsYfSadGFgeafpnc+5svnuZw9v9Y/H4msFbetoXUH9AQtcs+oCal5zG+AmBNZSqRROsdE6VczPPpwwn5lUCvI5XGXcFuo4X/tcQn9i6t314lgy1XYN6PAubbGDI1rnhlohMVy0XBwEi6xNWRT2vVx5ZxJmAfkSRE12n+AtdVrUQObr8cdzF9lei+DTd1fYz7QRiaJjkljEP4/J0GAiWv8z0JyDzbF9tlypJWkdWaO86eY=';
        let signature = ApiSigningUtil.getRSASignature(testBaseString,
            privateKey, passphrase);

        expect(signature).to.equal(testExpectedSignature);
    });
});


describe('ApiSigning Signature BaseString Test', function () {
    it('ApiSigning BaseString - Basic Test', function () {
        let urlPath = 'https://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊';
        let expectedBaseString = 'GET&https://loadtest-pvt.api.lab/api/v1/rest/level1/in-in/&ap=裕廊坊 心邻坊&apex_l1_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l1_ig_nonce=1355584618267440511&apex_l1_ig_signature_method=HMACSHA256&apex_l1_ig_timestamp=1502175057654&apex_l1_ig_version=1.0';

        let baseProps = {
            'authPrefix': 'Apex_L1_IG',
            'signatureMethod': 'HMACSHA256',
            'appId': 'loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ',
            'urlPath': urlPath,
            'httpMethod': 'get',
            'formData': null,
            'nonce': '1355584618267440511',
            'timestamp': '1502175057654',

        };

        let baseString = ApiSigningUtil.getSignatureBaseString(baseProps);

        expect(baseString).to.equal(expectedBaseString);
    });

    it('ApiSigning Signature BaseString - With Form Data', function () {
        let urlPath = 'https://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊';
        let expectedBaseString = 'POST&https://loadtest-pvt.api.lab/api/v1/rest/level1/in-in/&ap=裕廊坊 心邻坊&apex_l1_ig_app_id=loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ&apex_l1_ig_nonce=6584351262900708156&apex_l1_ig_signature_method=HMACSHA256&apex_l1_ig_timestamp=1502184161702&apex_l1_ig_version=1.0&param1=data1';
        let formData = {'param1': 'data1'};

        let baseProps = {
            'authPrefix': 'Apex_L1_IG',
            'signatureMethod': 'HMACSHA256',
            'appId': 'loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ',
            'urlPath': urlPath,
            'httpMethod': 'post',
            'formData': formData,
            'nonce': '6584351262900708156',
            'timestamp': '1502184161702',

        };

        let baseString = ApiSigningUtil.getSignatureBaseString(baseProps);

        expect(baseString).to.equal(expectedBaseString);
    });

    it('ApiSigning BaseString - Invalid Url 01', function () {
        let urlPath = 'ftp://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊';

        let baseProps = {
            'authPrefix': 'Apex_L1_IG',
            'signatureMethod': 'HMACSHA256',
            'appId': 'loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ',
            'urlPath': urlPath,
            'httpMethod': 'post',
            'formData': null,
            'nonce': '6584351262900708156',
            'timestamp': '1502184161702',

        };
        expect(ApiSigningUtil.getSignatureBaseString.bind(ApiSigningUtil,
            baseProps)).to.throw('Support http and https protocol only!');
    });

    it('ApiSigning BaseString - Invalid Url 02', function () {
        let urlPath = '://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊';

        let baseProps = {
            'authPrefix': 'Apex_L1_IG',
            'signatureMethod': 'HMACSHA256',
            'appId': 'loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ',
            'urlPath': urlPath,
            'httpMethod': 'post',
            'formData': null,
            'nonce': '6584351262900708156',
            'timestamp': '1502184161702',

        };
        expect(ApiSigningUtil.getSignatureBaseString.bind(ApiSigningUtil,
            baseProps)).
            to.
            throw(
                'Invalid URL: ://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊');
    });

    it('ApiSigning BaseString - Invalid Protocol 03', function () {
        let urlPath = 'smtp://loadtest-pvt.api.lab:443/api/v1/rest/level1/in-in/?ap=裕廊坊%20心邻坊';

        let baseProps = {
            'authPrefix': 'Apex_L1_IG',
            'signatureMethod': 'HMACSHA256',
            'appId': 'loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ',
            'urlPath': urlPath,
            'httpMethod': 'post',
            'formData': null,
            'nonce': '6584351262900708156',
            'timestamp': '1502184161702',

        };
        expect(ApiSigningUtil.getSignatureBaseString.bind(ApiSigningUtil,
            baseProps)).to.throw('Support http and https protocol only!');
    });
});

describe('ApiSigning Signature Token Test', function () {

    let realm = 'https://example.com';
    let authPrefixL1 = 'Apex_l1_ig';
    let authPrefixL2 = 'Apex_l2_ig';
    let httpMethod = 'get';
    let urlPath = 'https://example.com/api/v1/resources';
    let appId = 'loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ';
    let secret = 'ffef0c5087f8dc24a3f122e1e2040cdeb5f72c73';
    let nonce = '-5816789581922453013';
    let timestamp = '1502199514462';

    let expectedTokenL1 = 'Apex_l1_ig realm="https://example.com", apex_l1_ig_timestamp="1502199514462", apex_l1_ig_nonce="-5816789581922453013", apex_l1_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", apex_l1_ig_signature_method="HMACSHA256", apex_l1_ig_signature="ua32WiJ7FfDOZKuaaVDJyF12Yq0a8leTt5KAtHcTQc0=", apex_l1_ig_version="1.0"';
    let expectedTokenL2 = 'Apex_l2_ig realm="https://example.com", apex_l2_ig_timestamp="1502199514462", apex_l2_ig_nonce="-5816789581922453013", apex_l2_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", apex_l2_ig_signature_method="SHA256withRSA", apex_l2_ig_signature="rIb8tCUt2gghoZ0FsRTmDcbngW8UjeEs8UdMLC7y/ptmTyo1D8D4wZ0BPVJj3wB/r/VqiqGkl9axow2pTXM8jfZ0bavhIokqRNucv1yoEhsoGy6QnxeXymi2MJI+0XtUhsyIwwmNqVSCzFCFmviIGgPtGqGJ7+w6ABTupw/v38BExiKHbiMYnG1SzYXkv/qaQfEntrzgeWyPi8LxEX2p/6NxE7j3eRfBWXgipXNOoomGrPDcuRVGi2lxZntNqpVyTYKZbcXkFf/ZJNSaUcCTX97zebWFKB8F6cui7clLznqcQFwgLzamt9xDVu4FU56xjVvd2eqUZ+h5W2OX9QPm2IgCFqSpXSrziDFagi7tUVwLr3QstiW3qLxCXdMMYNPjewAe5vN0MJsSitadKIfNh9r4geWyB8dyuHATGiFSYITRY9n8k0CWjjEAOto94XPw3Fw/M9DV/8nLiHow2d+ul+IQijc8P72kIGi6b0fjXYDzq06v7WnNvl9vC5DY2gCaD4hFrzFX1jC9S4jKodGIUN0Xb1LNxw/mnjhACHL/tWBcu9SZ5HwHZSzRoBsKWZJPhiF+bqsvny3h4jJfg68l6SuqC9SzENtytJrEzGIZBxTW5hxfKBUVjIu6CoW2F54bbet7O8N63R3j8N3Q4HhWiFuXVDRBBpko/eMfNccfxrM=", apex_l2_ig_version="1.0"';
    let certFileName = path.join(process.cwd(),
        'spec/cert/ssc.alpha.example.com.pem');
    let passphrase = 'passwordpem';


    it('Api Signed Signature  Token - Basic L1 Test', function () {

        let reqProps = {
            'authPrefix': authPrefixL1,
            'realm': realm,
            'appId': appId,
            'secret': secret,
            'urlPath': urlPath,
            'httpMethod': httpMethod,
            'formData': null,
            'nonce': nonce,
            'timestamp': timestamp,
        };

        let sigToken = ApiSigningUtil.getSignatureToken(reqProps);
        expect(sigToken).to.equal(expectedTokenL1);
    });

    it('Api Signed Signature  Token - Basic L2 Test with cert file',
        function () {

            let reqProps = {
                'authPrefix': authPrefixL2,
                'realm': realm,
                'appId': appId,
                'urlPath': urlPath,
                'httpMethod': httpMethod,
                'certFileName': certFileName,
                'passphrase': passphrase,
                'nonce': nonce,
                'timestamp': timestamp,
            };

            let sigToken = ApiSigningUtil.getSignatureToken(reqProps);
            expect(sigToken).to.equal(expectedTokenL2);
        });

    it('Api Signed Signature Token - Basic L2 Test with cert string',
        function () {
            const certString = ApiSigningUtil.getPrivateKeyFromPem(
                certFileName);

            let reqProps = {
                'authPrefix': authPrefixL2,
                'realm': realm,
                'appId': appId,
                'urlPath': urlPath,
                'httpMethod': httpMethod,
                'certString': certString,
                'passphrase': passphrase,
                'nonce': nonce,
                'timestamp': timestamp,
            };

            let sigToken = ApiSigningUtil.getSignatureToken(reqProps);
            expect(sigToken).to.equal(expectedTokenL2);
        });

    it('Api Signed Signature Token - Wrong PassPhrase', function () {
        let expectedMessage = 'error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt';
        let reqProps = {
            'authPrefix': authPrefixL2,
            'realm': realm,
            'appId': appId,
            'urlPath': urlPath,
            'httpMethod': httpMethod,
            'certFileName': certFileName,
            'passphrase': 'wrong',
            'nonce': nonce,
            'timestamp': timestamp,
        };

        expect(ApiSigningUtil.getSignatureToken.bind(ApiSigningUtil, reqProps)).
            to.
            throw(expectedMessage);
    });

    it('Api Signed Signature  Token - Not Supported Cert Type', function () {
        let testFileName = path.join(process.cwd(),
            'spec/cert/ssc.alpha.example.com.p12');
        let expectedMessage = 'error:0906D06C:PEM routines:PEM_read_bio:no start line';
        let reqProps = {
            'authPrefix': authPrefixL2,
            'realm': realm,
            'appId': appId,
            'urlPath': urlPath,
            'httpMethod': httpMethod,
            'certFileName': testFileName,
            'passphrase': passphrase,
            'nonce': nonce,
            'timestamp': timestamp,
        };
        expect(ApiSigningUtil.getSignatureToken.bind(ApiSigningUtil, reqProps)).
            to.
            throw(expectedMessage);
    });

    it('Api Signed Signature Token - Invalid File Name', function () {
        let testFileName = path.join(process.cwd(),
            'spec/cert/alphaX.apex.gov.sg.p12');
        let expectedMessage = 'ENOENT: no such file or directory';
        let reqProps = {
            'authPrefix': authPrefixL2,
            'realm': realm,
            'appId': appId,
            'urlPath': urlPath,
            'httpMethod': httpMethod,
            'certFileName': testFileName,
            'passphrase': passphrase,
            'nonce': nonce,
            'timestamp': timestamp,
        };
        expect(ApiSigningUtil.getSignatureToken.bind(ApiSigningUtil, reqProps)).
            to.
            throw(expectedMessage);
    });
});

describe('ApiSigning (Deprecated) Token Test', function () {
    let realm = 'https://example.com';
    let authPrefixL1 = 'Apex_l1_ig';
    let authPrefixL2 = 'Apex_l2_ig';
    let httpMethod = 'get';
    let url = 'https://example.com/api/v1/resources';
    let appId = 'loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ';
    let secret = 'ffef0c5087f8dc24a3f122e1e2040cdeb5f72c73';
    let nonce = '-5816789581922453013';
    let timestamp = '1502199514462';

    let expectedTokenL1 = 'Apex_l1_ig realm="https://example.com", apex_l1_ig_timestamp="1502199514462", apex_l1_ig_nonce="-5816789581922453013", apex_l1_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", apex_l1_ig_signature_method="HMACSHA256", apex_l1_ig_signature="ua32WiJ7FfDOZKuaaVDJyF12Yq0a8leTt5KAtHcTQc0=", apex_l1_ig_version="1.0"';
    let expectedTokenL2 = 'Apex_l2_ig realm="https://example.com", apex_l2_ig_timestamp="1502199514462", apex_l2_ig_nonce="-5816789581922453013", apex_l2_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", apex_l2_ig_signature_method="SHA256withRSA", apex_l2_ig_signature="rIb8tCUt2gghoZ0FsRTmDcbngW8UjeEs8UdMLC7y/ptmTyo1D8D4wZ0BPVJj3wB/r/VqiqGkl9axow2pTXM8jfZ0bavhIokqRNucv1yoEhsoGy6QnxeXymi2MJI+0XtUhsyIwwmNqVSCzFCFmviIGgPtGqGJ7+w6ABTupw/v38BExiKHbiMYnG1SzYXkv/qaQfEntrzgeWyPi8LxEX2p/6NxE7j3eRfBWXgipXNOoomGrPDcuRVGi2lxZntNqpVyTYKZbcXkFf/ZJNSaUcCTX97zebWFKB8F6cui7clLznqcQFwgLzamt9xDVu4FU56xjVvd2eqUZ+h5W2OX9QPm2IgCFqSpXSrziDFagi7tUVwLr3QstiW3qLxCXdMMYNPjewAe5vN0MJsSitadKIfNh9r4geWyB8dyuHATGiFSYITRY9n8k0CWjjEAOto94XPw3Fw/M9DV/8nLiHow2d+ul+IQijc8P72kIGi6b0fjXYDzq06v7WnNvl9vC5DY2gCaD4hFrzFX1jC9S4jKodGIUN0Xb1LNxw/mnjhACHL/tWBcu9SZ5HwHZSzRoBsKWZJPhiF+bqsvny3h4jJfg68l6SuqC9SzENtytJrEzGIZBxTW5hxfKBUVjIu6CoW2F54bbet7O8N63R3j8N3Q4HhWiFuXVDRBBpko/eMfNccfxrM=", apex_l2_ig_version="1.0"';
    let certFileName = path.join(process.cwd(),
        'spec/cert/ssc.alpha.example.com.pem');
    let certString = ApiSigningUtil.getPrivateKeyFromPem(certFileName);
    let passphrase = 'passwordpem';

    let liveTestToggle = true;

    it('Api Signed Token - Basic L1 Test', function () {
        let token = ApiSigningUtil.getTokenFromSecret(realm, authPrefixL1,
            httpMethod,
            url, appId, secret, null, nonce, timestamp);
        expect(token).to.equal(expectedTokenL1);
    });

    it('Api Signed Token - Basic L2 Test with cert file', function () {
        let token = ApiSigningUtil.getTokenFromCertFileName(realm, authPrefixL2,
            httpMethod,
            url, appId, null, passphrase, certFileName, nonce, timestamp);
        expect(token).to.equal(expectedTokenL2);
    });

    it('Api Signed Token - Basic L2 Test with cert string', function () {

        let token = ApiSigningUtil.getTokenFromCertString(realm, authPrefixL2,
            httpMethod,
            url, appId, null, passphrase, certString, nonce, timestamp);
        expect(token).to.equal(expectedTokenL2);
    });

    it('Api Signed Token - Wrong PassPhrase for Cert String', function () {
        let expectedMessage = 'error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt';
        expect(ApiSigningUtil.getTokenFromCertString.bind(ApiSigningUtil, realm,
            authPrefixL2,
            httpMethod, url, appId, null, passphrase + 'x', certString,
            nonce, timestamp)).to.throw(expectedMessage);
    });

    it('Api Signed Token - Wrong PassPhrase for Cert File', function () {
        let expectedMessage = 'error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt';
        expect(
            ApiSigningUtil.getTokenFromCertFileName.bind(ApiSigningUtil, realm,
                authPrefixL2,
                httpMethod, url, appId, null, passphrase + 'x', certFileName,
                nonce, timestamp)).to.throw(expectedMessage);
    });

    it('Api Signed Token - Not Supported Cert Type for Cert File', function () {
        let testFileName = path.join(process.cwd(),
            'spec/cert/ssc.alpha.example.com.p12');
        let expectedMessage = 'error:0906D06C:PEM routines:PEM_read_bio:no start line';
        expect(
            ApiSigningUtil.getTokenFromCertFileName.bind(ApiSigningUtil, realm,
                authPrefixL2,
                httpMethod, url, appId, null, passphrase, testFileName, nonce,
                timestamp)).to.throw(expectedMessage);
    });

    it('Api Signed Token - Invalid File Name for Cert File', function () {
        let testFileName = path.join(process.cwd(),
            'spec/cert/alphaX.apex.gov.sg.p12');
        let expectedMessage = 'ENOENT: no such file or directory';
        expect(
            ApiSigningUtil.getTokenFromCertFileName.bind(ApiSigningUtil, realm,
                authPrefixL2,
                httpMethod, url, appId, null, passphrase, testFileName, nonce,
                timestamp)).to.throw(expectedMessage);
    });

    if (!liveTestToggle) {
        it('Api Signed Token - L0 Live Test', function (done) {
            let liveUrl = 'https://example.com/api/v1/resource';
            let httpMethod = 'get';

            ApiSigningUtil.sendRequest(liveUrl, null, null, httpMethod).
                then(function (data) {
                    expect(data.status).to.equal(200);
                    done();
                }).
                catch(function (error) {
                    done(JSON.stringify(error));
                });
        });

        it('Api Signed Token - L1 Live Test', function (done) {
            let liveUrl = 'https://example.com/api/v1/resource';
            let token = ApiSigningUtil.getToken(realm, authPrefixL1, httpMethod,
                liveUrl, appId, secret);

            ApiSigningUtil.sendRequest(liveUrl, token, null, httpMethod).
                then(function (data) {
                    expect(data.status).to.equal(200);
                    done();
                }).
                catch(function (error) {
                    done(JSON.stringify(error));
                });
        });

        it('Api Signed Token - L2 Live Test', function (done) {
            let liveUrl = 'https://example.com/api/v1/resource';
            let token = ApiSigningUtil.getToken(realm, authPrefixL2, httpMethod,
                liveUrl, appId, null, null, passphrase, certFileName);

            ApiSigningUtil.sendRequest(liveUrl, token, null, httpMethod).
                then(function (data) {
                    expect(data.status).to.equal(200);
                    done();
                }).
                catch(function (error) {
                    done(JSON.stringify(error));
                });
        });
    }
});
