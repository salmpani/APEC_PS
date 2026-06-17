const crypto = require("crypto");

function createLegacyTokenKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });
}

function signLegacyPayload(payload) {
  const signer = crypto.createSign("sha1");
  signer.update(payload);
  return signer;
}

module.exports = { createLegacyTokenKeyPair, signLegacyPayload };
