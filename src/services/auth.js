import axios from "axios";
import "dotenv/config";
import fs from "fs";
import https from "https";
import httpSignature from "http-signature";
import crypto from "crypto";

export function getToken(clientID) {
  const hash = crypto.createHash("sha256");
  const body = {
    grant_type: "client_credentials"
  };
  const options = {
    host: process.env.ingURL,
    method: "post",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Digest: `SHA-256=${Buffer.from(
        hash.update(JSON.stringify(body)).digest("hex")
      ).toString("base64")}`
    }
  };

  let req = https.request(options, response => {
    console.log(response);
  });
  req.on("error", e => {
    console.error(e);
  });
  signing(req, clientID);
  // axios(options)
  // .then(response => console.log(response))
  // .catch(e => console.log(e));
}

function signing(req, clientID) {
  const key = fs.readFileSync(process.env.SIGNING_KEY_FILE, "ascii");
  httpSignature.sign(req, {
    key: key,
    keyId: clientID
  });
  console.log(req.headers);
  //   req.end();
}
