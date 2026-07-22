import { generateKeyPairSync } from "node:crypto";

const { privateKey, publicKey } = generateKeyPairSync("x25519");
const privateJwk = privateKey.export({ format: "jwk" });
const publicJwk = publicKey.export({ format: "jwk" });

console.log(`LOCAL_PRIVATE_KEY=${fromBase64Url(privateJwk.d)}`);
console.log(`LOCAL_PUBLIC_KEY=${fromBase64Url(publicJwk.x)}`);

function fromBase64Url(value) {
	if (!value) throw new Error("Node did not export raw X25519 key material");
	return Buffer.from(value, "base64url").toString("base64");
}
