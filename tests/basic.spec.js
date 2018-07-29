import OasisApp from "index.js";

test("check address conversion", async () => {
  const pkStr = "17483e0883cf71e2fe4e12f42d1448d06f4274a73b9b6f560c5ed01a32745276";
  const pk = Buffer.from(pkStr, "hex");
  const addr = OasisApp.getBech32FromPK(pk);
  expect(addr).toEqual("oasis1zayruzyreac79ljwzt6z69zg6ph5ya988wdk74svtmgp5vn52fmqg7uz69");
});
