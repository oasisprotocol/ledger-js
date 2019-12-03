import OasisApp from "index.js";
import TransportNodeHid from "@ledgerhq/hw-transport-node-hid";
import { expect, test } from "jest";
import crypto from "crypto";

const ed25519 = require("ed25519-supercop");

const context = "oasis-core/consensus: tx for chain testing";

test("get version", async () => {
  const transport = await TransportNodeHid.create(1000);

  const app = new OasisApp(transport);
  const resp = await app.getVersion();
  console.log(resp);

  expect(resp.return_code).toEqual(0x9000);
  expect(resp.error_message).toEqual("No errors");
  expect(resp).toHaveProperty("test_mode");
  expect(resp).toHaveProperty("major");
  expect(resp).toHaveProperty("minor");
  expect(resp).toHaveProperty("patch");
  expect(resp.test_mode).toEqual(false);
});

test("publicKey", async () => {
  const transport = await TransportNodeHid.create(1000);
  const app = new OasisApp(transport);

  // Derivation path. First 3 items are automatically hardened!
  const path = [44, 118, 0, 0, 0];
  const resp = await app.publicKey(path);

  expect(resp.return_code).toEqual(0x9000);
  expect(resp.error_message).toEqual("No errors");
  expect(resp).toHaveProperty("pk");
  expect(resp.pk.length).toEqual(32);
  expect(resp.pk.toString("hex")).toEqual("17483e0883cf71e2fe4e12f42d1448d06f4274a73b9b6f560c5ed01a32745276");
});

test("getAddressAndPubKey", async () => {
  jest.setTimeout(60000);

  const transport = await TransportNodeHid.create(1000);
  const app = new OasisApp(transport);

  // Derivation path. First 3 items are automatically hardened!
  const path = [44, 118, 5, 0, 3];
  const resp = await app.getAddressAndPubKey(path);

  console.log(resp);

  expect(resp.return_code).toEqual(0x9000);
  expect(resp.error_message).toEqual("No errors");

  expect(resp).toHaveProperty("bech32_address");
  expect(resp).toHaveProperty("pk");

  expect(resp.bech32_address).toEqual("oasis1sd8kw7q6q7tt70ekqt9mc2gtzkfyqphsmtuqezjvrj74jmefgd5q09q0v");
  expect(resp.pk.length).toEqual(32);
});

test("showAddressAndPubKey", async () => {
  jest.setTimeout(60000);

  const transport = await TransportNodeHid.create(1000);
  const app = new OasisApp(transport);

  // Derivation path. First 3 items are automatically hardened!
  const path = [44, 118, 5, 0, 3];
  const resp = await app.showAddressAndPubKey(path);

  console.log(resp);

  expect(resp.return_code).toEqual(0x9000);
  expect(resp.error_message).toEqual("No errors");

  expect(resp).toHaveProperty("bech32_address");
  expect(resp).toHaveProperty("pk");

  expect(resp.bech32_address).toEqual("oasis1sd8kw7q6q7tt70ekqt9mc2gtzkfyqphsmtuqezjvrj74jmefgd5q09q0v");
  expect(resp.pk.length).toEqual(32);
});

test("appInfo", async () => {
  const transport = await TransportNodeHid.create(1000);
  const app = new OasisApp(transport);

  const resp = await app.appInfo();

  console.log(resp);

  expect(resp.return_code).toEqual(0x9000);
  expect(resp.error_message).toEqual("No errors");

  expect(resp).toHaveProperty("appName");
  expect(resp).toHaveProperty("appVersion");
  expect(resp).toHaveProperty("flagLen");
  expect(resp).toHaveProperty("flagsValue");
  expect(resp).toHaveProperty("flag_recovery");
  expect(resp).toHaveProperty("flag_signed_mcu_code");
  expect(resp).toHaveProperty("flag_onboarded");
  expect(resp).toHaveProperty("flag_pin_validated");
});

test("deviceInfo", async () => {
  const transport = await TransportNodeHid.create(1000);
  const app = new OasisApp(transport);

  const resp = await app.deviceInfo();

  console.log(resp);

  expect(resp.return_code).toEqual(0x9000);
  expect(resp.error_message).toEqual("No errors");

  expect(resp).toHaveProperty("targetId");
  expect(resp).toHaveProperty("seVersion");
  expect(resp).toHaveProperty("flag");
  expect(resp).toHaveProperty("mcuVersion");
});

test("sign_and_verify", async () => {
  jest.setTimeout(60000);

  const transport = await TransportNodeHid.create(1000);
  const app = new OasisApp(transport);

  // Derivation path. First 3 items are automatically hardened!
  const path = [44, 118, 0, 0, 0];
  const message = Buffer.from(
    "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq" +
      "83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
    "base64",
  );

  const responsePk = await app.publicKey(path);
  const responseSign = await app.sign(path, context, message);

  console.log(responsePk);
  console.log(responseSign);

  expect(responsePk.return_code).toEqual(0x9000);
  expect(responsePk.error_message).toEqual("No errors");
  expect(responseSign.return_code).toEqual(0x9000);
  expect(responseSign.error_message).toEqual("No errors");

  const hash = crypto.createHash("sha512");
  hash.update(context);
  hash.update(message);
  const msgHash = hash.digest();

  const valid = ed25519.verify(responseSign.signature, msgHash, responsePk.pk);
  expect(valid).toEqual(true);
});

test("sign_invalid", async () => {
  jest.setTimeout(60000);

  const transport = await TransportNodeHid.create(1000);
  const app = new OasisApp(transport);

  const path = [44, 118, 0, 0, 0]; // Derivation path. First 3 items are automatically hardened!
  let invalidMessage = Buffer.from(
    "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq" +
      "83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
    "base64",
  );
  invalidMessage += "1";

  const responseSign = await app.sign(path, context, invalidMessage);

  console.log(responseSign);
  expect(responseSign.return_code).toEqual(0x6984);
  expect(responseSign.error_message).toEqual("Data is invalid : Unexpected data type");
});
