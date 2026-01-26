import { z } from "zod";

export const AppSchema = z.object({
  id: z.string(),
  projectId: z.string(),
  name: z.string(),
  packageName: z.string(),
  signerDigestSha256: z.string(),
  createdAt: z.string()
});

export const CreateAppRequestSchema = z.object({
  name: z.string().min(1),
  packageName: z.string().min(1),
  signerDigestSha256: z.string().min(1)
});

export const CreateAppSecretResponseSchema = z.object({
  apiSecret: z.string(),
  prefix: z.string(),
  id: z.string()
});

export type App = z.infer<typeof AppSchema>;
export type CreateAppRequest = z.infer<typeof CreateAppRequestSchema>;
export type CreateAppSecretResponse = z.infer<typeof CreateAppSecretResponseSchema>;
