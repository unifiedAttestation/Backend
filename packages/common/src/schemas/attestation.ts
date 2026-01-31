import { z } from "zod";

export const DeviceProcessRequestSchema = z.object({
  projectId: z.string(),
  requestHash: z.string(),
  attestationChain: z.array(z.string()).min(1),
  deviceMeta: z
    .object({
      manufacturer: z.string().optional(),
      brand: z.string().optional(),
      model: z.string().optional(),
      device: z.string().optional(),
      buildFingerprint: z.string().optional()
    })
    .optional()
});

export const DeviceProcessResponseSchema = z.object({
  token: z.string(),
  expiresAt: z.string(),
  verdict: z.object({
    isTrusted: z.boolean(),
    reasonCodes: z.array(z.string())
  })
});

export const DecodeTokenRequestSchema = z.object({
  projectId: z.string(),
  token: z.string(),
  expectedRequestHash: z.string().optional()
});

export const DecodeTokenResponseSchema = z.object({
  verdict: z.object({
    isTrusted: z.boolean(),
    reasonCodes: z.array(z.string())
  }),
  requestHash: z.string(),
  claims: z.object({
    iss: z.string(),
    projectId: z.string(),
    requestHash: z.string(),
    app: z.object({
      packageName: z.string(),
      signerDigests: z.array(z.string())
    }),
    deviceIntegrity: z.record(z.any())
  })
});

export type DeviceProcessRequest = z.infer<typeof DeviceProcessRequestSchema>;
export type DeviceProcessResponse = z.infer<typeof DeviceProcessResponseSchema>;
export type DecodeTokenRequest = z.infer<typeof DecodeTokenRequestSchema>;
export type DecodeTokenResponse = z.infer<typeof DecodeTokenResponseSchema>;
