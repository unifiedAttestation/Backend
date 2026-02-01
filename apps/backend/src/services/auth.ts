import argon2 from "argon2";
import jwt from "jsonwebtoken";
import { getPrisma } from "../lib/prisma";
import { loadConfig } from "../lib/config";

const DEFAULT_JWT_SECRET = "dev-secret-change-me";
let cachedJwtSecret: string | null = null;

function getJwtSecret() {
  if (cachedJwtSecret) return cachedJwtSecret;
  const config = loadConfig();
  cachedJwtSecret = config.jwtSecret || DEFAULT_JWT_SECRET;
  return cachedJwtSecret;
}

export type AuthTokens = { accessToken: string; refreshToken: string };

export async function registerUser(
  email: string,
  password: string,
  role: "app_dev" | "oem" | "admin"
) {
  const prisma = getPrisma();
  const passwordHash = await argon2.hash(password);
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      role,
      displayName: email.split("@")[0]
    }
  });

  if (role === "oem") {
    const org = await prisma.oemOrg.create({
      data: {
        name: `${email.split("@")[0]} OEM`,
        ownerUserId: user.id
      }
    });
    await prisma.user.update({ where: { id: user.id }, data: { oemOrgId: org.id } });
  }

  return user;
}

export async function verifyUser(email: string, password: string) {
  const prisma = getPrisma();
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return null;
  }
  if (user.disabledAt) {
    return null;
  }
  const ok = await argon2.verify(user.passwordHash, password);
  if (!ok) {
    return null;
  }
  return user;
}

export async function ensureDefaultAdmin() {
  const prisma = getPrisma();
  const existing = await prisma.user.findFirst({ where: { role: "admin" } });
  if (existing) {
    return;
  }
  await registerUser("admin", "admin", "admin");
}

export function issueTokens(
  userId: string,
  role: string,
  accessTtlMinutes: number,
  refreshTtlDays: number
): AuthTokens {
  const secret = getJwtSecret();
  const accessToken = jwt.sign({ sub: userId, role, type: "access" }, secret, {
    expiresIn: `${accessTtlMinutes}m`
  });
  const refreshToken = jwt.sign({ sub: userId, role, type: "refresh" }, secret, {
    expiresIn: `${refreshTtlDays}d`
  });
  return { accessToken, refreshToken };
}

export function verifyRefreshToken(token: string) {
  const payload = jwt.verify(token, getJwtSecret()) as jwt.JwtPayload;
  if (payload.type !== "refresh") {
    throw new Error("Invalid refresh token");
  }
  return payload;
}

export function verifyAccessToken(token: string) {
  const payload = jwt.verify(token, getJwtSecret()) as jwt.JwtPayload;
  if (payload.type !== "access") {
    throw new Error("Invalid access token");
  }
  return payload;
}
