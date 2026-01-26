import { describe, expect, it } from "vitest";
import { validateTokenClaims } from "../src/services/tokenValidation";

describe("decode token validation", () => {
  it("accepts matching project and request hash", () => {
    const payload = {
      projectId: "com.example.app",
      requestHash: "abcd",
      exp: Math.floor(Date.now() / 1000) + 60
    };
    const requestHash = validateTokenClaims(payload as any, "com.example.app", "abcd");
    expect(requestHash).toBe("abcd");
  });

  it("rejects mismatched request hash", () => {
    const payload = {
      projectId: "com.example.app",
      requestHash: "abcd",
      exp: Math.floor(Date.now() / 1000) + 60
    };
    expect(() => validateTokenClaims(payload as any, "com.example.app", "deadbeef")).toThrow();
  });
});
