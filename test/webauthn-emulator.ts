import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import type { webcrypto } from "node:crypto";
import { fromB64Url, toB64Url } from "../src/security/crypto.js";

/**
 * 最小虚拟认证器：生成 ES256 密钥对，构造 "none" attestation 与 assertion。
 * 只覆盖 uni-auth 所需的 WebAuthn 子集（P-256 / none fmt / UP+UV 标志），
 * 用于端到端验证服务端 verify 流程，不模拟真实认证器的全部行为。
 */

function concat(...arrs: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function u16be(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

function u32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

// —— CBOR 子集（uint / negint / bytes / text / map）——

function cborHead(major: number, n: number): Uint8Array {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 0x100) return new Uint8Array([(major << 5) | 24, n]);
  return new Uint8Array([(major << 5) | 25, (n >> 8) & 0xff, n & 0xff]);
}

function cborUint(n: number): Uint8Array {
  return cborHead(0, n);
}

function cborNeg(n: number): Uint8Array {
  return cborHead(1, -n - 1);
}

function cborBytes(b: Uint8Array): Uint8Array {
  return concat(cborHead(2, b.length), b);
}

function cborText(s: string): Uint8Array {
  return concat(cborHead(3, new TextEncoder().encode(s).length), new TextEncoder().encode(s));
}

function cborMap(entries: [Uint8Array, Uint8Array][]): Uint8Array {
  return concat(cborHead(5, entries.length), ...entries.map(([k, v]) => concat(k, v)));
}

function coseKey(pub: webcrypto.JsonWebKey): Uint8Array {
  return cborMap([
    [cborUint(1), cborUint(2)], // kty: EC2
    [cborUint(3), cborNeg(-7)], // alg: ES256
    [cborNeg(-1), cborUint(1)], // crv: P-256
    [cborNeg(-2), cborBytes(fromB64Url(pub.x!))], // x
    [cborNeg(-3), cborBytes(fromB64Url(pub.y!))], // y
  ]);
}

async function authData(
  rpID: string,
  flags: number,
  counter: number,
  attested?: { credId: Uint8Array; cose: Uint8Array }
): Promise<Uint8Array> {
  const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpID)));
  const parts = [rpIdHash, new Uint8Array([flags]), u32be(counter)];
  if (attested) {
    parts.push(new Uint8Array(16), u16be(attested.credId.length), attested.credId, attested.cose);
  }
  return concat(...parts);
}

/** raw r||s (64 字节) → DER ASN.1 */
function toDer(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array): Uint8Array => {
    let start = 0;
    while (start < b.length - 1 && b[start] === 0) start++;
    let v = b.slice(start);
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

export class VirtualAuthenticator {
  readonly rawId: Uint8Array;
  counter = 0;
  private keyPair: webcrypto.CryptoKeyPair;

  private constructor(keyPair: webcrypto.CryptoKeyPair, rawId: Uint8Array) {
    this.keyPair = keyPair;
    this.rawId = rawId;
  }

  static async create(): Promise<VirtualAuthenticator> {
    const keyPair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as webcrypto.CryptoKeyPair;
    return new VirtualAuthenticator(keyPair, crypto.getRandomValues(new Uint8Array(32)));
  }

  async registration(rpID: string, origin: string, challenge: string): Promise<RegistrationResponseJSON> {
    const clientDataJSON = JSON.stringify({ type: "webauthn.create", challenge, origin });
    const pubJwk = (await crypto.subtle.exportKey("jwk", this.keyPair.publicKey)) as webcrypto.JsonWebKey;
    const cose = coseKey(pubJwk);
    // flags: UP(0x01) | UV(0x04) | AT(0x40)；注册时 counter 报 0（与多数真实认证器一致）
    const ad = await authData(rpID, 0x45, this.counter, { credId: this.rawId, cose });
    const attestationObject = cborMap([
      [cborText("fmt"), cborText("none")],
      [cborText("attStmt"), cborMap([])],
      [cborText("authData"), cborBytes(ad)],
    ]);
    return {
      id: toB64Url(this.rawId),
      rawId: toB64Url(this.rawId),
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: toB64Url(new TextEncoder().encode(clientDataJSON)),
        attestationObject: toB64Url(attestationObject),
        transports: ["internal"],
      },
    };
  }

  async assertion(rpID: string, origin: string, challenge: string): Promise<AuthenticationResponseJSON> {
    const clientDataJSON = JSON.stringify({ type: "webauthn.get", challenge, origin });
    this.counter += 1;
    // flags: UP(0x01) | UV(0x04)
    const ad = await authData(rpID, 0x05, this.counter);
    const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(clientDataJSON)));
    const sigRaw = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.keyPair.privateKey, concat(ad, clientHash))
    );
    return {
      id: toB64Url(this.rawId),
      rawId: toB64Url(this.rawId),
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: toB64Url(new TextEncoder().encode(clientDataJSON)),
        authenticatorData: toB64Url(ad),
        signature: toB64Url(toDer(sigRaw)),
      },
    };
  }
}


