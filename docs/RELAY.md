# Secret Relay extension boundary

**Not implemented in this release.** Capability discovery reports `relay: false`; there is no raw secret read, browser-fill, or arbitrary relay endpoint.

A future relay should share Keyloom's encrypted storage and human approval, but remain a separately enabled capability:

1. The requester names an item/field reference, a destination, an operation and a short expiry. No plaintext secret is included in the request or approval receipt.
2. A human approves the specific operation. A global CLI write grant must not implicitly grant secret reads or relay permission.
3. Command injection uses explicitly selected child-process stdin or environment; no secret is placed in command-line arguments or stdout.
4. Browser relay requires an exact target Origin/frame, a short-lived single-use lease, and no wildcard CORS. It must not be a long-running localhost password server.
5. Receipts and audit records contain references, target, time and result only; not passwords, recovery material, transport keys or decrypted payloads.
6. Locking or closing revokes unused leases.

Browser filling necessarily places a credential in the destination page. A downstream automation tool could still read it back; instructions against DOM snapshots/screenshots are helpful but do not turn an untrusted agent into a secure consumer. Do not market relay as protection against malicious same-user agents or malicious destination applications.
