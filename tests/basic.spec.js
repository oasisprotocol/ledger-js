import OasisApp from "index.js";
import { serializePathv1 } from "../src/helperV1";

const context = "oasis-core/consensus: tx for chain testing";

test("check address conversion", async () => {
  const pkStr = "17483e0883cf71e2fe4e12f42d1448d06f4274a73b9b6f560c5ed01a32745276";
  const pk = Buffer.from(pkStr, "hex");
  const addr = OasisApp.getBech32FromPK(pk);
  expect(addr).toEqual("oasis1zayruzyreac79ljwzt6z69zg6ph5ya988wdk74svtmgp5vn52fmqg7uz69");
});

test("check prepare chunks function", async () => {
  const serializedPath = serializePathv1([44, 123, 5, 0, 3]);
  const message = Buffer.from(
      "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq" +
        "83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
      "base64",
    );

  const chunks = OasisApp.prepareChunks(serializedPath, context, message);

  // Expect first chunk to be path
  expect(chunks[0]).toEqual(serializedPath);
  // First chunk should be path and second should have context + message so at least 2 chunks
  expect(chunks.length).toBeGreaterThan(1);
});

test("Verify prepare chunk function with empty context", async () => {
  const serializedPath = serializePathv1([44, 123, 5, 0, 3]);
  const message = Buffer.from(
      "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq" +
        "83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
      "base64",
    );
  const context = '';

  const chunks = OasisApp.prepareChunks(serializedPath, context, message);

  // First byte should be 0 (length of context)
  expect(chunks[1][0]).toEqual(0x00);
});

test("Test prepareChunks with context bigger than 255 bytes", async () => {
  const serializedPath = serializePathv1([44, 123, 5, 0, 3]);
  const message = Buffer.from(
      "pGNmZWWiY2dhcwBmYW1vdW50QGRib2R5omd4ZmVyX3RvWCBkNhaFWEyIEubmS3EVtRLTanD3U+vDV5fke4Obyq" +
        "83CWt4ZmVyX3Rva2Vuc0Blbm9uY2UAZm1ldGhvZHBzdGFraW5nLlRyYW5zZmVy",
      "base64",
    );
  const context = 'A'.repeat(256);

  try {
    const chunks = OasisApp.prepareChunks(serializedPath, context, message);
  } catch (e) {
    expect(e).toEqual(new Error("Maximum supported context size is 255 bytes"));
  }
});
