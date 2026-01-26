import jwt from "jsonwebtoken";
import { HttpError } from "../lib/errors";

export function validateTokenClaims(
  payload: jwt.JwtPayload,
  projectId: string,
  expectedRequestHash?: string
) {
  if (payload.projectId !== projectId) {
    throw new HttpError(400, "PROJECT_MISMATCH", "Token projectId mismatch");
  }
  if (payload.exp && payload.exp * 1000 < Date.now()) {
    throw new HttpError(400, "TOKEN_EXPIRED", "Token expired");
  }
  const requestHash = payload.requestHash as string;
  if (expectedRequestHash && expectedRequestHash !== requestHash) {
    throw new HttpError(400, "REQUEST_HASH_MISMATCH", "requestHash mismatch");
  }
  return requestHash;
}
