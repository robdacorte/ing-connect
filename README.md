# ING-CONNECT

This package is a SDK no official to connect to ING Bank API with Node.js.

ING Connect is designed to allow you to access PSD2 and Non PSD2 ING APIs with your existing Node.js application with minimal effort. The SDK will take care of calculating the digest, generating the date, signing the request and determing the headers as well as making the actual request.

ING developer portal. https://developer.ing.com/openbanking/get-started

## Installation

`npm i --save ing-connect`

once this package has been installed it'll require some .env params

| Keys | Values |
|------|--------|
|**SIGNING_KEY_FILE**| Key generated as this [documentation](https://developer.ing.com/api-marketplace/marketplace/2d00fd5f-88cd-4416-bbca-f309ebb03bfe/documentation#step-2-generate-and-upload-the-certificates) explains|
|**SIGNING_PASSWORD**| Password of the key generated avobe|
|**TLS_CERIFICATE_FILE**||
|**TLS_KEY_FILE**||

