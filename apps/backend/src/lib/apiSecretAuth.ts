import { FastifyRequest } from "fastify";
import { HttpError } from "./errors";

export function getApiSecret(request: FastifyRequest, headerName: string) {
  const value = request.headers[headerName.toLowerCase()];
  if (!value || Array.isArray(value)) {
    return null;
  }
  return value;
}

export function requireApiSecret(request: FastifyRequest, headerName: string) {
  const apiSecret = getApiSecret(request, headerName);
  if (!apiSecret) {
    throw new HttpError(401, "UNAUTHORIZED", "Missing API secret");
  }
  return apiSecret;
}
