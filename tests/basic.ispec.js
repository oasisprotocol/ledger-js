import TransportNodeHid from "@ledgerhq/hw-transport-node-hid";
import { expect, test } from "@jest/globals";
import { createHash } from "crypto";
import OasisApp from "../src/index";

const ed25519 = require("ed25519-supercop");
const secp256k1 = require("secp256k1/elliptic");
const sha512 = require("js-sha512");

let transport = {};
jest.setTimeout(120000);

beforeAll(async () => {
  transport = await TransportNodeHid.create(1000);
});

describe("Integration", function () {
  test("get version", async () => {
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
    const app = new OasisApp(transport);

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 474, 0, 0, 0];
    const resp = await app.publicKey(path);

    expect(resp.return_code).toEqual(0x9000);
    expect(resp.error_message).toEqual("No errors");
    expect(resp).toHaveProperty("pk");
    expect(resp.pk.length).toEqual(32);
    expect(resp.pk.toString("hex")).toEqual(
      "97e72e6e83ec39eb98d7e9189513aba662a08a210b9974b0f7197458483c7161",
    );
  });

  test("getAddressAndPubKey_Ed25519", async () => {
    const app = new OasisApp(transport);

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 474, 5, 0, 3];
    const resp = await app.getAddressAndPubKey_ed25519(path);

    console.log(resp);

    expect(resp.return_code).toEqual(0x9000);
    expect(resp.error_message).toEqual("No errors");

    expect(resp).toHaveProperty("bech32_address");
    expect(resp).toHaveProperty("pk");

    expect(resp.bech32_address).toEqual("oasis1qphdkldpttpsj2j3l9sde9h26cwpfwqwwuhvruyu");
    expect(resp.pk.length).toEqual(32);
  });

  test("showAddressAndPubKey_Ed25519", async () => {
    const app = new OasisApp(transport);

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 474, 5, 0, 3];
    const resp = await app.showAddressAndPubKey_ed25519(path);

    console.log(resp);

    expect(resp.return_code).toEqual(0x9000);
    expect(resp.error_message).toEqual("No errors");

    expect(resp).toHaveProperty("bech32_address");
    expect(resp).toHaveProperty("pk");

    expect(resp.bech32_address).toEqual("oasis1qphdkldpttpsj2j3l9sde9h26cwpfwqwwuhvruyu");
    expect(resp.pk.length).toEqual(32);
  });

  test("getAddressAndPubKey_Secp256k1", async () => {
    const app = new OasisApp(transport);

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 60, 0];
    const resp = await app.getAddressAndPubKey_secp256k1(path);

    console.log(resp);

    expect(resp.return_code).toEqual(0x9000);
    expect(resp.error_message).toEqual("No errors");

    expect(resp).toHaveProperty("hex_address");
    expect(resp).toHaveProperty("pk");

    expect(resp.hex_address).toEqual("95e5e3c1bdd92cd4a0c14c62480db5867946281d");
    expect(resp.pk.toString("hex")).toEqual(
      "021853d93524119eeb31ab0b06f1dcb068f84943bb230dfa10b1292f47af643575",
    );
    expect(resp.pk.length).toEqual(33);
  });

  test("showAddressAndPubKey_Secp256k1", async () => {
    const app = new OasisApp(transport);

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 60, 0];
    const resp = await app.showAddressAndPubKey_secp256k1(path);

    console.log(resp);

    expect(resp.return_code).toEqual(0x9000);
    expect(resp.error_message).toEqual("No errors");

    expect(resp).toHaveProperty("hex_address");
    expect(resp).toHaveProperty("pk");

    expect(resp.hex_address).toEqual("95e5e3c1bdd92cd4a0c14c62480db5867946281d");
    expect(resp.pk.toString("hex")).toEqual(
      "021853d93524119eeb31ab0b06f1dcb068f84943bb230dfa10b1292f47af643575",
    );
    expect(resp.pk.length).toEqual(33);
  });

  test("appInfo", async () => {
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

  test("sign_and_verify_ed25519", async () => {
    const app = new OasisApp(transport);

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 474, 0, 0, 0];
    const context =
      "oasis-core/consensus: tx for chain bc1c715319132305795fa86bd32e93291aaacbfb5b5955f3ba78bdba413af9e1";
    const message = Buffer.from(
      "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omRmcm9tVQAGaeylE0pICHuqRvArp3IYjeXN22ZhbW91bnRAZW5vbmNlAGZtZXRob2Rwc3Rha2luZy5XaXRoZHJhdw==",
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

    const hash = createHash("sha512-256");
    hash.update(context);
    hash.update(message);
    const msgHash = Buffer.from(hash.digest());

    console.log(Buffer.from(responseSign.signature).toString("hex"));
    console.log(Buffer.from(msgHash).toString("hex"));
    console.log(Buffer.from(responsePk.pk).toString("hex"));

    const valid = ed25519.verify(responseSign.signature, msgHash, responsePk.pk);
    expect(valid).toEqual(true);
  });

  test("sign_and_verify_pt_ed25519", async () => {
    const app = new OasisApp(transport);
    const path = [44, 474, 0, 0, 0];
    const meta = Buffer.from(
      "ompydW50aW1lX2lkeEAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBlMmVhYTk5ZmMwMDhmODdmbWNoYWluX2NvbnRleHR4QGIxMWIzNjllMGRhNWJiMjMwYjIyMDEyN2Y1ZTdiMjQyZDM4NWVmOGM2ZjU0OTA2MjQzZjMwYWY2M2M4MTU1MzU=",
      "base64",
    );

    const txBlob = Buffer.from(
      "o2F2AWJhaaJic2mBomVub25jZQBsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhZ2VkMjU1MTlYIDXD8zVt2FNk/roDVLVFraEJ0b2zi/XWEmgX24xyz9aRY2ZlZaJmYW1vdW50gkBAcmNvbnNlbnN1c19tZXNzYWdlcwFkY2FsbKJkYm9keaJidG9VAMjQ9FnbOOXMMcp35m0sRFbcvrUCZmFtb3VudIJAQGZtZXRob2RxY29uc2Vuc3VzLkRlcG9zaXQ=",
      "base64",
    );

    const sigCtx = Buffer.from(
      "oasis-runtime-sdk/tx: v0 for chain 03e5935652dc03c4a97e07ab2383bfbcc806a6760f872c1782a7ea560f4f7738",
    );

    const pkResponse = await app.getAddressAndPubKey_ed25519(path);
    console.log(pkResponse);
    expect(pkResponse.return_code).toEqual(0x9000);
    expect(pkResponse.error_message).toEqual("No errors");

    // do not wait here..
    const resp = await app.signPtEd25519(path, meta, txBlob);

    console.log(resp);

    expect(resp.return_code).toEqual(0x9000);
    expect(resp.error_message).toEqual("No errors");

    const hasher = sha512.sha512_256.update(sigCtx);
    hasher.update(txBlob);
    const msgHash = Buffer.from(hasher.hex(), "hex");

    // Now verify the signature
    const valid = ed25519.verify(resp.signature, msgHash, pkResponse.pk);
    expect(valid).toEqual(true);
  });

  test("sign_and_verify_pt_secp256k1", async () => {
    const app = new OasisApp(transport);
    const path = [44, 60, 0, 0, 0];
    const meta = Buffer.from(
      "o2dvcmlnX3RveCg3MDlFRWJkOTc5MzI4QTJCMzYwNUExNjA5MTVERUIyNkUxODZhYkY4anJ1bnRpbWVfaWR4QDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDcyYzgyMTVlNjBkNWJjYTdtY2hhaW5fY29udGV4dHhANTAzMDRmOThkZGI2NTY2MjBlYTgxN2NjMTQ0NmM0MDE3NTJhMDVhMjQ5YjM2YzliOTBkYmE0NjE2ODI5OTc3YQ==",
      "base64",
    );

    const txBlob = Buffer.from(
      "o2F2AWJhaaJic2mBomVub25jZQFsYWRkcmVzc19zcGVjoWlzaWduYXR1cmWhbHNlY3AyNTZrMWV0aFghAwF6GNjbybMzhi3XRj5R1oTiMMkO1nAwB7NZAlH1X4BEY2ZlZaJjZ2FzGQ+gZmFtb3VudIJEB1vNFUNGT09kY2FsbKJkYm9keaJidG9VADDXgI3ukLc0acA65kYHwNVuBE4rZmFtb3VudIJARFdCVENmbWV0aG9kcWFjY291bnRzLlRyYW5zZmVy",
      "base64",
    );

    const sigCtx = Buffer.from(
      "oasis-runtime-sdk/tx: v0 for chain 7f1eb9fa832a02ccda132d330f342dbef92c0817bf73eeea12020552f1d62f86",
    );

    const pkResponse = await app.getAddressAndPubKey_secp256k1(path);
    console.log(pkResponse);
    expect(pkResponse.return_code).toEqual(0x9000);
    expect(pkResponse.error_message).toEqual("No errors");

    // do not wait here..
    const resp = await app.signPtSecp256k1(path, meta, txBlob);

    console.log(resp);

    expect(resp.return_code).toEqual(0x9000);
    expect(resp.error_message).toEqual("No errors");

    const hasher = sha512.sha512_256.update(sigCtx);
    hasher.update(txBlob);
    const msgHash = Buffer.from(hasher.hex(), "hex");

    const signatureRS = Uint8Array.from(resp.signature).slice(0, -1);

    const signatureOk = secp256k1.ecdsaVerify(signatureRS, msgHash, pkResponse.pk);
    expect(signatureOk).toEqual(true);
  });

  test("sign_invalid", async () => {
    const app = new OasisApp(transport);

    const path = [44, 474, 0, 0, 0]; // Derivation path. First 3 items are automatically hardened!
    const context =
      "oasis-core/consensus: tx for chain bc1c715319132305795fa86bd32e93291aaacbfb5b5955f3ba78bdba413af9e1";
    let invalidMessage = Buffer.from(
      "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq" +
        "83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
      "base64",
    );
    invalidMessage += "1";

    const responseSign = await app.sign(path, context, invalidMessage);

    console.log(responseSign);
    expect(responseSign.return_code).toEqual(0x6984);
    expect(responseSign.error_message).toEqual("Data is invalid : Root item should be a map");
  });
});
