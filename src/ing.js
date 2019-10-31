import https from 'https';
import axios from 'axios';
import crypto from 'crypto';
import querystring from 'querystring';
import fs from 'fs';
import 'dotenv/config';
import uuid from 'uuid/v1';

export default class ING {
    constructor(options) {
        const {clientID, sandbox} = options
        this.SANDBOX = !!sandbox;
        this.apiBasePath = !!sandbox ? "https://api.sandbox.ing.com" : "https://api.ing.com";
        this.SIGNING_KEY_FILE = fs.readFileSync(process.env.SIGNING_KEY_FILE);
        this.SIGNING_PASSWORD = process.env.SIGNING_PASSWORD;
        this.TLS_CERIFICATE_FILE = fs.readFileSync(process.env.TLS_CERIFICATE_FILE);
        this.TLS_KEY_FILE = fs.readFileSync(process.env.TLS_KEY_FILE);
        this.clientId = clientID;
        this.agent = this.getHttpsAgent();
    }
    getHttpsAgent(){
        return new https.Agent({
            rejectUnauthorized: false,
            cert: this.TLS_CERIFICATE_FILE,
            key: this.TLS_KEY_FILE
        });
    }
    async requestShowcase(access_token) {
        return await this.requestAPI("get", "/greetings/single", access_token);
    }

    async requestAuthorizationUrl(scope, countryCode, accessToken) {
        const urlParams = querystring.stringify({
            scope,
            "country_code": countryCode
        });
        const result = await this.requestAPI("get", `/oauth2/authorization-server-url?${urlParams}`, accessToken);
        return result.location;
    }

    async requestCustomerAccessToken(authorizationCode, accessToken) {
        if (this.SANDBOX) {
            authorizationCode = "694d6ca9-1310-4d83-8dbb-e819c1ee6b80";
        }

        const bodyData = {
            "grant_type": "authorization_code",
            "code": authorizationCode,
            "redirect_uri": "xxx"
        }

        const result = await this.requestAPI("post", "/oauth2/token", accessToken, bodyData);
        return result.access_token;
    }

    async requestAccounts(customerAccessToken) {
        const result = await this.requestAPI("get", "/v1/accounts", customerAccessToken);
        return result.accounts;
    }

    async requestBalances(customerAccessToken, accountId) {
        const result = await this.requestAPI("get", "/v1/accounts/" + accountId + "/balances", customerAccessToken);
        return result.accounts;
    }

    async requestTransactions(customerAccessToken, accountId) {
        const result = await this.requestAPI("get", "/v1/accounts/" + accountId + "/transactions", customerAccessToken);
        return result.accounts;
    }

    async requestAPI(httpMethod, reqPath, access_token, bodyData = {}) {
        // URL encode body
        const body = querystring.stringify(bodyData);

        // Create parameters
        const digest = crypto.createHash('sha256').update(body).digest('base64');
        const reqId = uuid();
        const dateString = new Date().toUTCString();

        // Create signature
        const signature = this.generateSignature(httpMethod, reqPath, dateString, digest, reqId);

        // Create options
        const options = {
            method: httpMethod,
            headers: {
                'Authorization': `Bearer ${access_token}`,
                'Signature': `keyId="${this.clientId}",algorithm="rsa-sha256",headers="(request-target) date digest x-ing-reqid",signature="${signature}"`,
                'X-ING-ReqID': reqId,
                'Date': dateString,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Digest': `SHA-256=${digest}`
            },
            data: body,
            url: this.apiBasePath + reqPath,
            httpsAgent: this.agent
        };

        // Return result
        const result = await axios(options);
        return result.data;
    }

    // Request Access Token
    async requestAccessToken(scope) {
        const bodyData = {
            grant_type: 'client_credentials',
            scope
        }

        // URL encode body
        let body = querystring.stringify(bodyData);
        if (this.SANDBOX) {
            body = 'grant_type=client_credentials&scope=greetings%3Aview';
            // body = 'grant_type=client_credentials&scope=create_order+granting+payment-requests+payment-requests%3Aview+payment-requests%3Acreate+payment-requests%3Aclose+virtual-ledger-accounts%3Afund-reservation%3Acreate+virtual-ledger-accounts%3Afund-reservation%3Adelete+virtual-ledger-accounts%3Abalance%3Aview';
        }

        // Create parameters
        const digest = crypto.createHash('sha256').update(body).digest('base64');
        const reqId = uuid();
        const dateString = new Date().toUTCString();

        // Create signature
        const signature = this.generateSignature('post', "/oauth2/token", dateString, digest, reqId);

        // Create options
        let options = {
            method: 'post',
            headers: {
                'Authorization': `Signature keyId="${this.clientId}",algorithm="rsa-sha256",headers="(request-target) date digest x-ing-reqid",signature="${signature}"`,
                'X-ING-ReqID': reqId,
                'Date': dateString,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Digest': `SHA-256=${digest}`
            },
            data: body,
            url: this.apiBasePath + "/oauth2/token",
            httpsAgent: this.agent
        };
        
        if (this.SANDBOX) {
            options = {
                method: 'post',
                headers: {
                    'Authorization': `Signature keyId="${this.clientId}",algorithm="rsa-sha256",headers="(request-target) date digest x-ing-reqid",signature="${signature}"`,
                    'Signature': `keyId="${this.clientId}",algorithm="rsa-sha256",headers="(request-target) date digest x-ing-reqid",signature="${signature}"`,
                    'X-ING-ReqID': reqId,
                    'Date': dateString,
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Digest': `SHA-256=${digest}`
                },
                data: body,
                url: this.apiBasePath + "/oauth2/token",
                httpsAgent: this.agent
            };
        }

        // Return result
        const result = await axios(options);
        return result.data.access_token;
    }

    generateSignature(httpMethod, reqPath, dateString, digest, reqId) {
        const signingString = `(request-target): ${httpMethod} ${reqPath}\ndate: ${dateString}\ndigest: SHA-256=${digest}\nx-ing-reqid: ${reqId}`;

        const hash = crypto.createSign('SHA256');
        hash.update(signingString);
        return hash.sign({ key: this.SIGNING_KEY_FILE, passphrase: this.SIGNING_PASSWORD }, "base64");
    }
}