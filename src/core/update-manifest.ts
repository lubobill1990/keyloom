import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { lstatSync } from "node:fs";
import { currentTarget, layout, type Target } from "./platform";
import { asciiJson, base64, exactKeys, VaultError } from "./strict";
import { hashFile, noLinks } from "./files";

export const IDENTIFIER = "io.github.lubobill1990.keyloom";
export const REPOSITORY = "lubobill1990/keyloom";
export const PUBLIC_KEY = "ixNl+V1D7q4ueWbh+tErF5LE9NVrVRBdn9pdhPiC2Lw=";
export type Payload = { schema: 1; version: string; platform: Target; asset: string; url: string; sha256: string; size: number };
export type SignedManifest = { payload: Payload; signature: string };
export function version(value: unknown): number[] {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d{0,8})\.(?:0|[1-9]\d{0,8})\.(?:0|[1-9]\d{0,8})$/.test(value)) throw new VaultError("更新只接受稳定的 major.minor.patch 版本");
  return value.split(".").map(Number);
}
export function newer(candidate: string, current: string) {
  const left = version(candidate), right = version(current);
  for (let index = 0; index < 3; index++) { if (left[index] !== right[index]) return left[index]! > right[index]!; }
  return false;
}
export function archiveName(value: string, selected: Target = currentTarget()) { version(value); return `keyloom-${value}-${selected}-update.zip`; }
export function manifestUrl(selected: Target = currentTarget()) { return `https://github.com/${REPOSITORY}/releases/latest/download/${layout(selected).feed}`; }
export function payload(input: unknown, selected: Target = currentTarget()): Payload {
  exactKeys(input, ["schema", "version", "platform", "asset", "url", "sha256", "size"]);
  if (typeof input.version !== "string") throw new VaultError("更新版本无效");
  const name = archiveName(input.version, selected);
  if (input.schema !== 1 || input.platform !== selected || input.asset !== name || input.url !== `https://github.com/${REPOSITORY}/releases/download/v${input.version}/${name}`
    || typeof input.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(input.sha256)
    || typeof input.size !== "number" || !Number.isSafeInteger(input.size) || input.size < 1 || input.size > 512 * 1024 * 1024) throw new VaultError("更新清单未绑定受信任的仓库、平台、版本和文件");
  return { schema: 1, version: input.version, platform: selected, asset: name, url: input.url, sha256: input.sha256, size: input.size };
}
function publicKey(value = PUBLIC_KEY) {
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: base64(value, 32).toString("base64url") }, format: "jwk" });
}
export function verifyManifest(input: unknown, selected: Target = currentTarget(), publicBytes = PUBLIC_KEY): SignedManifest {
  exactKeys(input, ["payload", "signature"]);
  const value = payload(input.payload, selected), signature = base64(input.signature, 64);
  if (!verify(null, Buffer.from(asciiJson(value), "ascii"), publicKey(publicBytes), signature)) throw new VaultError("更新签名验证失败，不会安装");
  return { payload: value, signature: signature.toString("base64") };
}
export function signManifest(input: unknown, privateBytes: Uint8Array, selected: Target): SignedManifest {
  if (privateBytes.length !== 32) throw new VaultError("发布签名密钥长度无效");
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), privateBytes]), format: "der", type: "pkcs8" });
  const exported = createPublicKey(key).export({ format: "jwk" });
  if (typeof exported.x !== "string" || Buffer.from(exported.x, "base64url").toString("base64") !== PUBLIC_KEY) throw new VaultError("发布私钥与内置公钥不匹配，拒绝隐式轮换");
  const value = payload(input, selected);
  const document = { payload: value, signature: sign(null, Buffer.from(asciiJson(value), "ascii"), key).toString("base64") };
  return verifyManifest(document, selected);
}
export function verifyArchive(path: string, value: Payload) {
  noLinks(path);
  if (!lstatSync(path).isFile() || lstatSync(path).size !== value.size || hashFile(path) !== value.sha256) throw new VaultError("更新包的大小或 SHA-256 不匹配签名");
}
