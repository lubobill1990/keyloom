import { expect, test } from "bun:test";
import { lstatSync } from "node:fs";
import { alive, identity } from "./processes";

test("native process identity uses the executable image, not its mutable display name", async () => {
  const current = await identity(process.pid);
  expect(current).not.toBeNull();
  if (!current) throw new Error("Missing current process.");
  expect(lstatSync(current.executable).isFile()).toBe(true);
  const title = process.title;
  try {
    process.title = "keyloom-native-identity-test";
    expect((await identity(process.pid))?.executable).toBe(current.executable);
  } finally { process.title = title; }
  expect(await alive(current)).toBe(true);
  expect(await alive({ ...current, started: current.started + "-different" })).toBe(false);
  expect(await alive({ ...current, executable: current.executable + ".wrong" })).toBe(false);
}, 15_000);
