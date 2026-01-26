import { z } from "zod";

export const RegisterRequestSchema = z.object({
  email: z.string().email(),
  password: z.string().min(5),
  role: z.enum(["app_dev", "oem", "admin"]).default("app_dev")
});

export const AuthResponseSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string()
});

export const LoginRequestSchema = z.object({
  email: z.string().min(1),
  password: z.string().min(5)
});

export const RefreshRequestSchema = z.object({
  refreshToken: z.string()
});

export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;
export type LoginRequest = z.infer<typeof LoginRequestSchema>;
export type RefreshRequest = z.infer<typeof RefreshRequestSchema>;
export type AuthResponse = z.infer<typeof AuthResponseSchema>;
