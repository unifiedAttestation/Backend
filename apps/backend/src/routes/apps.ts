import { FastifyInstance } from "fastify";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  AppSchema,
  CreateAppRequestSchema,
  CreateAppSecretResponseSchema
} from "@ua/common";
import { getPrisma } from "../lib/prisma";
import { errorResponse } from "../lib/errors";
import { requireUser } from "../lib/auth";
import { generateApiSecret } from "../services/apiSecrets";

export default async function appManagementRoutes(app: FastifyInstance) {
  app.get(
    "/",
    {
      schema: {
        response: {
          200: { type: "array", items: zodToJsonSchema(AppSchema) }
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      if (user.role !== "app_dev" && user.role !== "admin") {
        reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
        return;
      }
      const prisma = getPrisma();
      const apps = await prisma.app.findMany({
        where: user.role === "admin" ? undefined : { ownerUserId: user.sub as string },
        select: {
          id: true,
          projectId: true,
          name: true,
          signerDigestSha256: true,
          createdAt: true
        }
      });
      reply.send(apps);
    }
  );

  app.post(
    "/",
    {
      schema: {
        body: zodToJsonSchema(CreateAppRequestSchema),
        response: {
          200: zodToJsonSchema(CreateAppSecretResponseSchema)
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      if (user.role !== "app_dev" && user.role !== "admin") {
        reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
        return;
      }
      const prisma = getPrisma();
      const body = CreateAppRequestSchema.parse(request.body);
      const secret = generateApiSecret();
      const created = await prisma.app.create({
        data: {
          name: body.name,
          projectId: body.projectId,
          signerDigestSha256: body.signerDigestSha256.toLowerCase(),
          apiSecretHash: secret.hash,
          apiSecretPrefix: secret.prefix,
          ownerUserId: user.sub as string
        }
      });
      reply.send({ apiSecret: secret.raw, prefix: created.apiSecretPrefix, id: created.id });
    }
  );

  app.post(
    "/:appId/rotate-secret",
    {
      schema: {
        response: {
          200: zodToJsonSchema(CreateAppSecretResponseSchema)
        }
      }
    },
    async (request, reply) => {
      const user = requireUser(request);
      if (user.role !== "app_dev" && user.role !== "admin") {
        reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
        return;
      }
      const prisma = getPrisma();
      const { appId } = request.params as { appId: string };
      const appRecord = await prisma.app.findFirst({
        where: user.role === "admin" ? { id: appId } : { id: appId, ownerUserId: user.sub as string }
      });
      if (!appRecord) {
        reply.code(404).send(errorResponse("APP_NOT_FOUND", "App not found"));
        return;
      }
      const secret = generateApiSecret();
      await prisma.app.update({
        where: { id: appRecord.id },
        data: {
          apiSecretHash: secret.hash,
          apiSecretPrefix: secret.prefix
        }
      });
      reply.send({ apiSecret: secret.raw, prefix: secret.prefix, id: appRecord.id });
    }
  );

  app.get("/:appId/reports", async (request, reply) => {
    const user = requireUser(request);
    if (user.role !== "app_dev" && user.role !== "admin") {
      reply.code(403).send(errorResponse("FORBIDDEN", "App dev role required"));
      return;
    }
    const prisma = getPrisma();
    const { appId } = request.params as { appId: string };
    const appRecord = await prisma.app.findFirst({
      where: user.role === "admin" ? { id: appId } : { id: appId, ownerUserId: user.sub as string }
    });
    if (!appRecord) {
      reply.code(404).send(errorResponse("APP_NOT_FOUND", "App not found"));
      return;
    }
    const reports = await prisma.deviceReport.findMany({
      where: { projectId: appRecord.projectId },
      orderBy: { lastSeen: "desc" }
    });
    reply.send(reports);
  });
}
