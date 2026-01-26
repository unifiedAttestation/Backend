import crypto from "crypto";
import { getPrisma } from "../lib/prisma";

function hashSecret(raw: string): string {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

export function generateApiSecret(): { raw: string; prefix: string; hash: string } {
  const raw = `ua_secret_${crypto.randomBytes(24).toString("hex")}`;
  const prefix = raw.slice(0, 10);
  const hash = hashSecret(raw);
  return { raw, prefix, hash };
}

export async function verifyApiSecret(raw: string) {
  const prisma = getPrisma();
  const hash = hashSecret(raw);
  const app = await prisma.app.findFirst({
    where: {
      apiSecretHash: hash
    }
  });
  return app;
}
