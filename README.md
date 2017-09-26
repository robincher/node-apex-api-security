# APEX API Node JS Security Utility
[![Build Status](https://travis-ci.org/GovTechSG/node-apex-api-security.svg?branch=master)](https://travis-ci.org/GovTechSG/node-apex-api-security)
[![Coverage Status](https://coveralls.io/repos/github/GovTechSG/node-apex-api-security/badge.svg?branch=master)](https://coveralls.io/github/GovTechSG/node-apex-api-security?branch=development)
[![Known Vulnerabilities](https://snyk.io/test/github/govtechsg/node-apex-api-security/badge.svg)](https://snyk.io/test/github/govtechsg/node-apex-api-security)

A node helper utilities that form HTTP security header for API authenticationgit. There are two interfaces as of now, ApiSecurityUtil and ApiSigningUtil,which support different input parameter types.

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

## Walkthrough for ApiSigningUtil

**Preparing the request parameter (Dummy values)**

```
 let realm = 'http://tenant.com/token';
```

It identifies the fact that the message comes from the realm for your app

+ If the incoming message is not signed, the platform expects the AppID and doesn't look for the realm value.
+ If the incoming message is signed, the platform looks for the realm parameter. If it exists, the platform uses the same realm value when sending an authentication challenge. If the value isn't specified, the platform uses this value:

```
 let authPrefixL1 = 'Apex_l1_ig';
 let authPrefixL2 = 'Apex_l2_ig';
```

 Custom API Gateway specific Authorization scheme for a **specific gateway zone**. 
 
```
 let httpMethod = 'get';
```

 The Api HTTP Call operation method
 
```
 var url = "https://tenant.com/api/v1/resource";
 var appId = 'yourAppID';
```

API Gateway's App and Api related information that are generated and published through the community or developer portal.

```
var secret = 's0m3S3ecreT';
```
If you are authenticating with ApiSigningUtil L1 , please provide the App secret generated. 

***Note: Set it to null if you are using ApiSigningUtil L2 RSA256 Signing***

**Invoking the function for ApiSigningUtil**

Typically, you would only need to retrieve the generated signature token and append it to your HTTP request header

```
const ApiSigningUtil = require('<<package-name-defined').ApiSigningUtil;
let secToken = ApiSigningUtil.getToken(realm, authPrefix, httpMethod, urlPath, appId, secret, formJson, passphrase, certFileName, nonce, timestamp);

```

If you want to log while running the unit test , just set the log level to trace

```
ApiSigningUtil.setLogLevel('none');
```

## Walkthrough for ApiSecurityUtil

**Preparing the request parameter (Dummy values)**

```
let L1RequestParams = {
    "prefix": "apex_l1_eg,
    "method": "get",
    "url": "https://tenant.api/v1/test,
    "appid": "dummy,
    "secret": "dummy",
    "params": {},
    "formData": {}
}
```

```

let L2RequestParams = {
    "prefix": "apex_l1_eg,
    "method": "get",
    "url": "https://tenant.api/v1/test,
    "appid": "dummy,
    "secret": undefined,
    "params": {},
    "formData": {},
    "pemFileName": "./spec/cert/somepem.pem",
    "passphrase": "somepass",
}
```

***Note: Set secret to null or undefined if you are using ApiSecurity L2 RSA256 Signing (L2RequestParams)***

**Invoking the function for ApiSecurityUtil**

Same as above, just retrieve the token and append it to your HTTP request header

```
const ApiSecurityUtil = require('<<package-name-defined').ApiSecurityUtil;

let secToken = ApiSecurityUtil.getSecurityToken(<<RequestParams>);

```

## Security Signature Token Example
```
Apex_l2_ig realm="http://tenant.com/token", apex_l2_ig_timestamp="1502199514462", apex_l2_ig_nonce="-5816789581922453013", apex_l2_ig_app_id="loadtest-pvt-4Swyn7qwKeO32EXdH1dKTeIQ", 
apex_l2_ig_signature_method="SHA256withRSA", 
apex_l2_ig_signature="CH1GtfF2OYGYDAY5TH40Osez86mInZmgZETIOZCGvATBnjDcmCi6blkOlfUpGvzoccr9CA0wO8jL6VNh6cqPnVjO4bpVnSLQ8iiPOz4JK7kxJ4Cb19sX4pO6sx4srDmNqfnGOp5FeFx/rCr16ecvd3+HJF5sJEeOrDytr+HlOBf9pARVx5GroVSKxsKkXzto5XpJ2MN0Mu8eZA5BNJwune/TnnEy0oqjJWNSE+puGH4jMsp4hgLsJOwxJPS8Zg9dtPzoV60Gigxd7Yif2NqiFGI3oi0D3+sVv3QxURLPwCSE9ARyeenYhipG+6gncCR+tWEfaQBGyH9gnG6RtwZh3A=="
```

## Contributing

Easy as 1-2-3:

  + Step 1: Branch off from ```development``` and work on your feature or hotfix.
  + Step 2: Update the changelog.
  + Step 3: Create a pull request when you're done.

## References:
+ [Akana API Consumer Security](http://docs.akana.com/ag/cm_policies/using_api_consumer_app_sec_policy.htm)
+ [RSA and HMAC Request Signing Standard](http://tools.ietf.org/html/draft-cavage-http-signatures-05)

## Todo
+ JWT Token verification   

## Releases
+ Check out latest changes at CHANGELOG.md


