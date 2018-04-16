# APEX API Node.js Security Utility
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/eb0547096e2d4693b8cd19a87977f14f)](https://www.codacy.com/app/GovTech/node-apex-api-security?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=GovTechSG/node-apex-api-security&amp;utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.org/GovTechSG/node-apex-api-security.svg?branch=master)](https://travis-ci.org/GovTechSG/node-apex-api-security)
[![Coverage Status](https://coveralls.io/repos/github/GovTechSG/node-apex-api-security/badge.svg?branch=master)](https://coveralls.io/github/GovTechSG/node-apex-api-security?branch=master)
[![Known Vulnerabilities](https://snyk.io/test/github/govtechsg/node-apex-api-security/badge.svg)](https://snyk.io/test/github/govtechsg/node-apex-api-security)

A Javascript utility that generates HTTP security headers for authenticating with secured Apex endpoints, for Node.js.

## Table of Contents
- [Getting Started](#getting-started)
    * [API Usage](#api-usage)
    * [Security Signature Token Example](#security-signature-token-example)
- [Contributing](#contributing)
- [Release](#release)
- [License](#license)
- [References](#references)

## Getting Started

Add this package as a dependency in `package.json`.

```
"dependencies": {
    "node-apex-api-security": "git+https://github.com/GovTechSG/node-apex-api-security.git",
}
```

### Installation

```
$ npm install
```

### API Usage

#### `ApiSigningUtil.getSignatureToken(options)`

Returns a signature token used for authentication with a secured Apex API.

##### L1 Secured API

```javascript
const ApiSigningUtil = require('node-apex-api-security').ApiSigningUtil;

// Required options for L1 authentication
const requestOptions = {
    appId: 'my-app-id',                     // Apex App ID
    secret: 'my-app-secret',                // Apex App Secret
    authPrefix: 'apex_l1_eg',               // Authentication prefix, determined by authentication level and gateway type
    httpMethod: 'get',                      // HTTP method, e.g. GET/POST
    urlPath: 'https://my.apex.api.endpoint' // URL to Apex API
};

const L1SignatureToken = ApiSigningUtil.getSignatureToken(requestOptions);
```

##### L2 Secured API

```javascript
const ApiSigningUtil = require('node-apex-api-security').ApiSigningUtil;

// Required options for L2 authentication
const requestOptions = {
    appId: 'my-app-id',                       // Apex App ID
    certFileName: '/path/to/my/private.key',  // Path to private key used for L2 signature
    authPrefix: 'apex_l2_eg',                 // Authentication prefix, determined by authentication level and gateway type
    httpMethod: 'get',                        // HTTP method, e.g. GET/POST
    urlPath: 'https://my.apex.api.endpoint'   // URL to Apex API
};

const L2SignatureToken = ApiSigningUtil.getSignatureToken(requestOptions);
```

##### All Options

`appId`

Apex App ID. The API Gateway's App and Api information are generated and published through the community or developer portal.

```javascript
let appId = 'my-app-id';
```

`authPrefix`

Custom API Gateway specific Authorization scheme for a **specific gateway zone**. Takes 4 possible values.
 
```javascript
let authPrefix = 'Apex_l1_ig'; 
// or
let authPrefix = 'Apex_l1_eg';
// or
let authPrefix = 'Apex_l2_ig';
// or
let authPrefix = 'Apex_l2_eg';
```

`httpMethod`

 The API HTTP method
 
```javascript
let httpMethod = 'get';
```

`urlPath`

The full API endpoint
 
```javascript
let urlPath = "https://tenant.com/api/v1/resource";
```

`secret` - Required for L1 signature

If the API you are accessing is secured with an L1 policy, you need to provide the generated App secret that corresponds to the `appId` provided.

**Note: Set the secret to null or undefined if you are using ApiSigningUtil L2 RSA256 Signing**

```javascript
let secret = 's0m3S3ecreT'; 
```

`certString` or `certFileName`

If the API you are access is secured with an L2 policy, you need to provide the private key corresponding to the public key uploaded for `appId`.

Please provide either the path to your private key used to generate your L2 signature `certFileName` or the actual contents `certString`.

```javascript
let certFileName = '/path/to/my/private.key';
// or
let certString = '----BEGIN PRIVATE KEY ----\n ${private_key_contents} \n -----END PRIVATE KEY-----';
let passphrase = 'passphrase for the certString';
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

  




