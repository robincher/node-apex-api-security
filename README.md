# APEX API Node.js Security Utility
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/eb0547096e2d4693b8cd19a87977f14f)](https://www.codacy.com/app/GovTech/node-apex-api-security?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GovTechSG/node-apex-api-security&amp;utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.org/GovTechSG/node-apex-api-security.svg?branch=master)](https://travis-ci.org/GovTechSG/node-apex-api-security)
[![Coverage Status](https://coveralls.io/repos/github/GovTechSG/node-apex-api-security/badge.svg?branch=master)](https://coveralls.io/github/GovTechSG/node-apex-api-security?branch=master)
[![Known Vulnerabilities](https://snyk.io/test/github/govtechsg/node-apex-api-security/badge.svg)](https://snyk.io/test/github/govtechsg/node-apex-api-security)

A node helper utilities that form HTTP security header for API authentication. 

## Table of Contents
- [APEX API Node.js Security Utility](#apex-api-node.js-security-utility)
- [Getting Started](#getting-started)
    * [Interface Walkthrough](#walkthrough)
    * [Security Signature Token Example](#security-signature-token-example)
- [Contributing](#contributing)
- [Release](#release)
- [License](#license)
- [References](#references)

## Getting Started
Include this helper class in your project package json

```
  "dependencies": {
  "node-apex-api-security": "git+https://your-repo-location/node-apex-api-security.git",
  }
```

Re-build your node packages if needed

```
npm install
```

Test both interfaces.  Self-signed testing certificates can be located at spec/cert. 

```
npm test
```

Please update the values in the test cases if necessary.

### Walkthrough

**Preparing the request parameter (Dummy values)**


```
 let realm = 'http://tenant.com/token';
```

It identifies the fact that the message comes from the realm for your app

+ If the incoming message is not signed, the platform expects the AppID and doesn't look for the realm value.
+ If the incoming message is signed, the platform looks for the realm parameter. If it exists, the platform uses the same realm value when sending an authentication challenge. If the value isn't specified, the platform uses this value:

Custom API Gateway specific Authorization scheme for a **specific gateway zone**. 
 
```
 let authPrefixL1 = 'Apex_l1_ig';
 let authPrefixL2 = 'Apex_l2_ig';
```
 The Api HTTP Call operation method
 
```
 let httpMethod = 'get';
```

API Gateway's App and Api related information that are generated and published through the community or developer portal.
 
```
let urlPath = "https://tenant.com/api/v1/resource";
let appId = 'yourAppID';
```


If you are authenticating with ApiSigningUtil L1 , please provide the App secret generated. 

***Note: Set the secret to null or undefined if you are using ApiSigningUtil L2 RSA256 Signing***

```
let secret = 's0m3S3ecreT'; 
```

If you are authenticating with ApiSigningUtil L2 , please provide either  (certFileName) or the actual contents (certString). 

1)Signing certificate contents

```
let certString = 'Cert Contents here;;
let passphrase = 'passphrase for the certString';
```

2) Signing certificate's path and corresponding passphrase

```
let certFileName = './spec/cert/default.pem'; 
let passphrase = 'passphrase for the certFileName';
```

Request Data 

1) Form Data (x-www-form-urlencoded) - HTTP POST / HTTP PUT

```
let formData = {"key" : "value"};
```

2) Query Parameters  - HTTP GET

Append the query parameters on the url 

```
 urlPath = path + '?' + querystring.stringify(_.clone(queryParams));
```

Your urlPath should look something like this

```
https://test.com/v1/resources?host=https%3A%2F%2Fnd-sleetone1.api.dev&panelName=hello
```

**Invoking the function for ApiSigningUtil**

Typically, you only need to retrieve the generated signature token and append to the HTTP request header

Import the library

```
const ApiSigningUtil = require('<<package-name-defined').ApiSigningUtil;
```

Formulate the request object

```
let reqProps = {
    'authPrefix': <<authPrefixL1 or authPrefixL2, depending on your use case>>,
    'realm' : realm,
    'appId' : appId,
    'secret' : secret, //If you are authenticating with L1, else leave it blank
    'urlPath' : urlPath, //Append with query paramters if any for HTTP Get Request
    'httpMethod' : httpMethod,
    'formData' :  formData , //Append for PUT or POST request using form data 
    'certString' : certString,  //If you are authenticating L2 with the cert contents
    'certFileName' : certFilaName, //If you are authenticating L2 with a cert path
    'passphrase' : passphrase //For L2
    'nonce' : <<Can ignore this or set it as null as it will be auto-generated during runtime>>
    'timestamp' : <<Can ignore this or set it as null as it will be auto-generated during runtime>>
}
```

```
let sigToken = ApiSigningUtil.getSignatureToken(reqProps);

```

**Passing query param and x-form-urlencoded data**

Only populate the **formData** parameter if your API request have x-form-urlencoded data or query parameters. 

**Logging**

If you want to log while running the unit test , just set the log level to **trace**

```
ApiSigningUtil.setLogLevel('trace');
```

### Security Signature Token Example
```
Apex_l2_ig realm="http://tenant.com/token", apex_l2_ig_timestamp="1502199514462", apex_l2_ig_nonce="-5816789581922453013", apex_l2_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", 
apex_l2_ig_signature_method="SHA256withRSA", 
apex_l2_ig_signature="CH1GtfF2OYGYDAY5TH40Osez86mInZmgZETIOZCGvATBnjDcmCi6blkOlfUpGvzoccr9CA0wO8jL6VNh6cqPnVjO4bpVnSLQ8iiPOz4JK7kxJ4Cb19sX4pO6sx4srDmNqfnGOp5FeFx/rCr16ecvd3+HJF5sJEeOrDytr+HlOBf9pARVx5GroVSKxsKkXzto5XpJ2MN0Mu8eZA5BNJwune/TnnEy0oqjJWNSE+puGH4jMsp4hgLsJOwxJPS8Zg9dtPzoV60Gigxd7Yif2NqiFGI3oi0D3+sVv3QxURLPwCSE9ARyeenYhipG+6gncCR+tWEfaQBGyH9gnG6RtwZh3A=="
```

## Contributing
+ For more information about contributing PRs and issues, see [CONTRIBUTING.md](https://github.com/GovTechSG/node-apex-api-security/blob/master/.github/CONTRIBUTING.md).

## Release
+ See [CHANGELOG.md](CHANGELOG.md).

## License
[MIT LICENSE ](https://github.com/GovTechSG/node-apex-api-security/blob/master/LICENSE)

## References
+ [Akana API Consumer Security](http://docs.akana.com/ag/cm_policies/using_api_consumer_app_sec_policy.htm)
+ [RSA and HMAC Request Signing Standard](http://tools.ietf.org/html/draft-cavage-http-signatures-05)

  




