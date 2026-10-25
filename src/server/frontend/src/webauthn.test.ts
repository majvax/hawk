import { describe, expect, test } from "bun:test";

import {
  PasskeyCancelled,
  base64UrlToBytes,
  bytesToBase64Url,
  creationOptionsFromJson,
  credentialToJson,
  hostWithin,
  passkeyError,
  passkeysUsable,
  requestOptionsFromJson,
  withoutNulls,
} from "./webauthn.js";

const bytes = (...values: number[]): Uint8Array<ArrayBuffer> => new Uint8Array(values);
const buffer = (...values: number[]): ArrayBuffer => bytes(...values).buffer;

describe("webauthn", () => {
  test("base64url both ways", () => {
    expect(bytesToBase64Url(bytes())).toBe("");
    expect(bytesToBase64Url(bytes(0xfb, 0xff, 0xbf))).toBe("-_-_");
    expect(bytesToBase64Url(bytes(1, 2))).toBe("AQI");
    expect(bytesToBase64Url(buffer(1, 2, 3, 4))).toBe("AQIDBA");
    // A view into a larger buffer is only its own bytes.
    expect(bytesToBase64Url(new Uint8Array(buffer(9, 1, 2, 9), 1, 2))).toBe("AQI");
    expect([...base64UrlToBytes("-_-_")]).toEqual([0xfb, 0xff, 0xbf]);
    expect([...base64UrlToBytes("AQI")]).toEqual([1, 2]);
    // Padded and standard base64 too.
    expect([...base64UrlToBytes("AQI=")]).toEqual([1, 2]);
    expect([...base64UrlToBytes("+/+/")]).toEqual([0xfb, 0xff, 0xbf]);
    const random = crypto.getRandomValues(new Uint8Array(33));
    expect([...base64UrlToBytes(bytesToBase64Url(random))]).toEqual([...random]);
  });

  test("nulls go, at any depth", () => {
    expect(withoutNulls({ a: null, b: { c: null, d: 1 }, e: [{ f: null }] })).toEqual({ b: { d: 1 }, e: [{}] });
  });

  test("creation options: binary fields decoded, the rest kept", () => {
    const options = creationOptionsFromJson({
      publicKey: {
        rp: { id: "example.com", name: "Hawk" },
        user: { id: "AQI", name: "me@example.com", displayName: "me@example.com" },
        challenge: "AQIDBA",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        timeout: 120000,
        excludeCredentials: [{ type: "public-key", id: "-_-_", transports: ["usb"] }, { type: "public-key", id: "AQ" }],
        authenticatorSelection: { authenticatorAttachment: null, userVerification: "preferred" },
        attestation: "none",
      },
    });
    expect([...new Uint8Array(options.challenge as ArrayBuffer)]).toEqual([1, 2, 3, 4]);
    expect([...new Uint8Array(options.user.id as ArrayBuffer)]).toEqual([1, 2]);
    expect(options.user.name).toBe("me@example.com");
    expect(options.rp).toEqual({ id: "example.com", name: "Hawk" });
    expect(options.excludeCredentials?.map((credential) => [...new Uint8Array(credential.id as ArrayBuffer)])).toEqual([
      [0xfb, 0xff, 0xbf],
      [1],
    ]);
    expect(options.excludeCredentials?.[0]?.transports).toEqual(["usb"]);
    expect(options.excludeCredentials?.[1]).not.toHaveProperty("transports");
    expect(options.authenticatorSelection).toEqual({ userVerification: "preferred" });
    expect(options.timeout).toBe(120000);
  });

  test("request options: challenge and allowed credentials decoded", () => {
    const options = requestOptionsFromJson({
      publicKey: {
        challenge: "AQID",
        rpId: "example.com",
        allowCredentials: [{ type: "public-key", id: "AQ", transports: ["internal", "hybrid"] }],
        userVerification: "preferred",
        timeout: 120000,
      },
    });
    expect([...new Uint8Array(options.challenge as ArrayBuffer)]).toEqual([1, 2, 3]);
    expect(options.rpId).toBe("example.com");
    expect(options.allowCredentials?.[0]?.transports).toEqual(["internal", "hybrid"]);
    expect([...new Uint8Array(options.allowCredentials?.[0]?.id as ArrayBuffer)]).toEqual([1]);
  });

  test("answers as the relay reads them", () => {
    const registration = credentialToJson({
      id: "AQI",
      rawId: buffer(1, 2),
      type: "public-key",
      response: { clientDataJSON: buffer(3), attestationObject: buffer(4), getTransports: () => ["usb", "nfc"] },
      getClientExtensionResults: () => ({ credProps: { rk: false } }),
    });
    expect(registration).toEqual({
      id: "AQI",
      rawId: "AQI",
      type: "public-key",
      response: { clientDataJSON: "Aw", attestationObject: "BA", transports: ["usb", "nfc"] },
      clientExtensionResults: { credProps: { rk: false } },
    });

    const assertion = credentialToJson({
      id: "AQI",
      rawId: buffer(1, 2),
      type: "public-key",
      response: { clientDataJSON: buffer(3), authenticatorData: buffer(5), signature: buffer(6), userHandle: null },
    });
    expect(assertion.response).toEqual({ clientDataJSON: "Aw", authenticatorData: "BQ", signature: "Bg" });
    expect(assertion.clientExtensionResults).toEqual({});
  });

  test("passkeys are offered only under the RP ID, in a browser that has them", () => {
    expect(hostWithin("example.com", "example.com")).toBe(true);
    expect(hostWithin("Dash.Example.com", "example.com")).toBe(true);
    expect(hostWithin("badexample.com", "example.com")).toBe(false);
    expect(hostWithin("example.com", "dash.example.com")).toBe(false);

    const browser = { inApp: false, hostname: "relay.example.com", secure: true, supported: true };
    expect(passkeysUsable("relay.example.com", browser)).toBe(true);
    expect(passkeysUsable(null, browser)).toBe(false);
    expect(passkeysUsable("relay.example.com", { ...browser, hostname: "you.github.io" })).toBe(false);
    expect(passkeysUsable("relay.example.com", { ...browser, supported: false })).toBe(false);
    expect(passkeysUsable("relay.example.com", { ...browser, secure: false })).toBe(false);
    // The desktop app, even if a relay were set up for its host.
    expect(passkeysUsable("localhost", { ...browser, inApp: true, hostname: "tauri.localhost" })).toBe(false);
  });

  test("a closed prompt is a cancel, not a failure", () => {
    expect(passkeyError(new DOMException("timed out or not allowed", "NotAllowedError"))).toBeInstanceOf(PasskeyCancelled);
    expect(passkeyError(new DOMException("", "AbortError"))).toBeInstanceOf(PasskeyCancelled);
    expect(passkeyError(new DOMException("", "InvalidStateError")).message).toContain("already registered");
    expect(passkeyError(new DOMException("", "SecurityError"))).not.toBeInstanceOf(PasskeyCancelled);
    const plain = new Error("network");
    expect(passkeyError(plain)).toBe(plain);
  });
});
