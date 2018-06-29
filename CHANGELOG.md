# Change Log

## Added 
### V0.1.0
+ Initial release with HMAC256 and RSA256 signing utility
### V0.2.0
+ Additional interface , ApiSigningUtil, that take in parameters when forming RSA256 and HMAC256 security signature token
### V0.3.0
+ Update superagent version for security patch
### V0.4.0
+ Minor improvements and typo fix in index.js
### V0.4.1
+ There are now 3 variants to getToken in ApiSigningUtil.js
+ Typedefs has been added for ApiSigningUtil.js
### V0.4.2
+ Export typing
### V0.5.0
+ Allows client to pass in request as an object for ApiSigningUtil
+ Deprecate getToken interface for ApiSigningUtil
+ Deprecate ApiSecurityUtil
+ Update L1 and L2 to more representative method names
### V0.6.0
+ Recompile for Node 8
+ Update ApiSigningUtil URL interface
+ Update ApiSigningUtil test specification
### V0.6.1
+ Remove unused validator dependency
+ Add package-lock json
### V0.7.0
+ Remove ApiSecurityUtil and test class
+ Refine Readme
### V0.7.1
+ Add support to handle QueryString as parameter to the getSignatureToken API
### V0.7.2
+ Added default value for realm in getSignatureToken
### V0.7.4
+ Prepare for publishing and update package metadata
### V0.7.5
+ Added logic to getSignatureBaseString to generate nonce and timestamp.
### V0.7.6
+ Update package.json to fix sub-dependency vulnerabilities
### V0.7.7
+ Remove nonce node library