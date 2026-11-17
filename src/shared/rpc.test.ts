import { expect, test } from "bun:test";
import { defineElectrobunRPC } from "../../node_modules/electrobun/dist/api/shared/rpc";
import type { VaultRPC } from "./types";

test("vault RPC crosses the actual SDK proxy without colliding with Function.call", async () => {
  const bun = defineElectrobunRPC<VaultRPC, "bun">("bun", {
    handlers: { requests: { vault: () => ({ ok: true, data: "synthetic" }) }, messages: {} },
  });
  const view = defineElectrobunRPC<VaultRPC, "webview">("webview", {
    handlers: { requests: {}, messages: {} },
  });
  let bunReceive: ((packet: unknown) => void) | undefined;
  let viewReceive: ((packet: unknown) => void) | undefined;
  bun.setTransport({ send: (packet: unknown) => viewReceive?.(packet), registerHandler: (handler) => { bunReceive = handler; } });
  view.setTransport({ send: (packet: unknown) => bunReceive?.(packet), registerHandler: (handler) => { viewReceive = handler; } });
  expect(await view.request.vault({ method: "status" })).toEqual({ ok: true, data: "synthetic" });
});
