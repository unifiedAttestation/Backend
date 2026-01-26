import { FastifyInstance } from "fastify";
import { getPrisma } from "../lib/prisma";
import { requireUser } from "../lib/auth";
import { errorResponse } from "../lib/errors";

async function requireOemOrg(userId: string) {
  const prisma = getPrisma();
  const existing = await prisma.oemOrg.findFirst({ where: { ownerUserId: userId } });
  if (existing) {
    return existing;
  }
  return prisma.oemOrg.create({
    data: {
      name: `OEM-${userId}`,
      ownerUserId: userId
    }
  });
}

function requireOemRole(role: string, reply: any) {
  if (role !== "oem" && role !== "admin") {
    reply.code(403).send(errorResponse("FORBIDDEN", "OEM role required"));
    return false;
  }
  return true;
}

export default async function oemRoutes(app: FastifyInstance) {
  app.get("/profile", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    reply.send(org);
  });

  app.put("/profile", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const body = request.body as { name?: string; manufacturer?: string; brand?: string };
    const org = await requireOemOrg(user.sub as string);
    const updated = await prisma.oemOrg.update({
      where: { id: org.id },
      data: {
        name: body.name ?? org.name,
        manufacturer: body.manufacturer,
        brand: body.brand
      }
    });
    reply.send(updated);
  });

  app.get("/device-families", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const families = await prisma.deviceFamily.findMany({
      where: { oemOrgId: org.id },
      include: { trustAnchors: true }
    });
    const response = families.map((family) => ({
      id: family.id,
      name: family.name,
      codename: family.codename,
      model: family.model,
      manufacturer: family.manufacturer,
      brand: family.brand,
      trustAnchorIds: family.trustAnchors.map((link) => link.trustAnchorId),
      createdAt: family.createdAt
    }));
    reply.send(response);
  });

  app.post("/device-families", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const body = request.body as {
      name?: string;
      codename?: string;
      model?: string;
      manufacturer?: string;
      brand?: string;
      trustAnchorIds?: string[];
    };
    if (!body.name) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing device family name"));
      return;
    }
    const family = await prisma.deviceFamily.create({
      data: {
        name: body.name,
        codename: body.codename,
        model: body.model,
        manufacturer: body.manufacturer,
        brand: body.brand,
        oemOrgId: org.id,
        trustAnchors: body.trustAnchorIds
          ? {
              create: body.trustAnchorIds.map((anchorId) => ({
                trustAnchorId: anchorId
              }))
            }
          : undefined
      },
      include: { trustAnchors: true }
    });
    reply.send({
      id: family.id,
      name: family.name,
      codename: family.codename,
      model: family.model,
      manufacturer: family.manufacturer,
      brand: family.brand,
      trustAnchorIds: family.trustAnchors.map((link) => link.trustAnchorId),
      createdAt: family.createdAt
    });
  });

  app.put("/device-families/:familyId", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId } = request.params as { familyId: string };
    const body = request.body as {
      name?: string;
      codename?: string;
      model?: string;
      manufacturer?: string;
      brand?: string;
      trustAnchorIds?: string[];
    };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device family not found"));
      return;
    }
    if (body.trustAnchorIds) {
      await prisma.deviceFamilyTrustAnchor.deleteMany({
        where: { deviceFamilyId: family.id }
      });
      await prisma.deviceFamily.update({
        where: { id: family.id },
        data: {
          trustAnchors: {
            create: body.trustAnchorIds.map((anchorId) => ({ trustAnchorId: anchorId }))
          }
        }
      });
    }
    const updated = await prisma.deviceFamily.update({
      where: { id: family.id },
      data: {
        name: body.name ?? family.name,
        codename: body.codename ?? family.codename,
        model: body.model ?? family.model,
        manufacturer: body.manufacturer ?? family.manufacturer,
        brand: body.brand ?? family.brand
      },
      include: { trustAnchors: true }
    });
    reply.send({
      id: updated.id,
      name: updated.name,
      codename: updated.codename,
      model: updated.model,
      manufacturer: updated.manufacturer,
      brand: updated.brand,
      trustAnchorIds: updated.trustAnchors.map((link) => link.trustAnchorId),
      createdAt: updated.createdAt
    });
  });

  app.delete("/device-families/:familyId", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId } = request.params as { familyId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device family not found"));
      return;
    }
    await prisma.deviceFamilyTrustAnchor.deleteMany({ where: { deviceFamilyId: family.id } });
    await prisma.buildPolicy.deleteMany({ where: { deviceFamilyId: family.id } });
    await prisma.deviceFamily.delete({ where: { id: family.id } });
    reply.send({ ok: true });
  });

  app.get("/device-families/:familyId/builds", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId } = request.params as { familyId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device family not found"));
      return;
    }
    const builds = await prisma.buildPolicy.findMany({
      where: { deviceFamilyId: family.id },
      orderBy: { createdAt: "desc" }
    });
    reply.send(builds);
  });

  app.post("/device-families/:familyId/builds", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId } = request.params as { familyId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device family not found"));
      return;
    }
    const body = request.body as {
      name?: string;
      verifiedBootKeyHex?: string;
      verifiedBootHashHex?: string;
      osVersionRaw?: number;
      minOsPatchLevelRaw?: number;
      minVendorPatchLevelRaw?: number;
      minBootPatchLevelRaw?: number;
      expectedDeviceLocked?: boolean;
      expectedVerifiedBootState?: string;
      enabled?: boolean;
    };
    if (!body.name || !body.verifiedBootKeyHex) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing build name or verifiedBootKeyHex"));
      return;
    }
    const created = await prisma.buildPolicy.create({
      data: {
        deviceFamilyId: family.id,
        name: body.name,
        verifiedBootKeyHex: body.verifiedBootKeyHex.toLowerCase(),
        verifiedBootHashHex: body.verifiedBootHashHex?.toLowerCase(),
        osVersionRaw: body.osVersionRaw,
        minOsPatchLevelRaw: body.minOsPatchLevelRaw,
        minVendorPatchLevelRaw: body.minVendorPatchLevelRaw,
        minBootPatchLevelRaw: body.minBootPatchLevelRaw,
        expectedDeviceLocked: body.expectedDeviceLocked,
        expectedVerifiedBootState: body.expectedVerifiedBootState,
        enabled: body.enabled ?? true
      }
    });
    reply.send(created);
  });

  app.put("/device-families/:familyId/builds/:buildId", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId, buildId } = request.params as { familyId: string; buildId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device family not found"));
      return;
    }
    const build = await prisma.buildPolicy.findFirst({
      where: { id: buildId, deviceFamilyId: family.id }
    });
    if (!build) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Build policy not found"));
      return;
    }
    const body = request.body as {
      name?: string;
      verifiedBootKeyHex?: string;
      verifiedBootHashHex?: string | null;
      osVersionRaw?: number | null;
      minOsPatchLevelRaw?: number | null;
      minVendorPatchLevelRaw?: number | null;
      minBootPatchLevelRaw?: number | null;
      expectedDeviceLocked?: boolean | null;
      expectedVerifiedBootState?: string | null;
      enabled?: boolean;
    };
    const updated = await prisma.buildPolicy.update({
      where: { id: build.id },
      data: {
        name: body.name ?? build.name,
        verifiedBootKeyHex: body.verifiedBootKeyHex
          ? body.verifiedBootKeyHex.toLowerCase()
          : build.verifiedBootKeyHex,
        verifiedBootHashHex:
          body.verifiedBootHashHex === null
            ? null
            : body.verifiedBootHashHex
            ? body.verifiedBootHashHex.toLowerCase()
            : build.verifiedBootHashHex,
        osVersionRaw: body.osVersionRaw ?? build.osVersionRaw,
        minOsPatchLevelRaw: body.minOsPatchLevelRaw ?? build.minOsPatchLevelRaw,
        minVendorPatchLevelRaw: body.minVendorPatchLevelRaw ?? build.minVendorPatchLevelRaw,
        minBootPatchLevelRaw: body.minBootPatchLevelRaw ?? build.minBootPatchLevelRaw,
        expectedDeviceLocked:
          body.expectedDeviceLocked === undefined ? build.expectedDeviceLocked : body.expectedDeviceLocked,
        expectedVerifiedBootState:
          body.expectedVerifiedBootState === undefined
            ? build.expectedVerifiedBootState
            : body.expectedVerifiedBootState,
        enabled: body.enabled ?? build.enabled
      }
    });
    reply.send(updated);
  });

  app.delete("/device-families/:familyId/builds/:buildId", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const org = await requireOemOrg(user.sub as string);
    const prisma = getPrisma();
    const { familyId, buildId } = request.params as { familyId: string; buildId: string };
    const family = await prisma.deviceFamily.findFirst({
      where: { id: familyId, oemOrgId: org.id }
    });
    if (!family) {
      reply.code(404).send(errorResponse("NOT_FOUND", "Device family not found"));
      return;
    }
    await prisma.buildPolicy.delete({ where: { id: buildId } });
    reply.send({ ok: true });
  });

  app.get("/trust-anchors", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const anchors = await prisma.trustAnchor.findMany({ orderBy: { createdAt: "desc" } });
    reply.send(anchors);
  });

  app.post("/trust-anchors", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const body = request.body as { name?: string; pem?: string };
    if (!body.name || !body.pem) {
      reply.code(400).send(errorResponse("INVALID_REQUEST", "Missing trust anchor name or pem"));
      return;
    }
    const anchor = await prisma.trustAnchor.create({
      data: {
        name: body.name,
        pem: body.pem
      }
    });
    reply.send(anchor);
  });

  app.delete("/trust-anchors/:anchorId", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const { anchorId } = request.params as { anchorId: string };
    await prisma.deviceFamilyTrustAnchor.deleteMany({ where: { trustAnchorId: anchorId } });
    await prisma.trustAnchor.delete({ where: { id: anchorId } });
    reply.send({ ok: true });
  });

  app.get("/reports/failing-devices", async (request, reply) => {
    const user = requireUser(request);
    if (!requireOemRole(user.role as string, reply)) {
      return;
    }
    const prisma = getPrisma();
    const { deviceFamilyId } = request.query as { deviceFamilyId?: string };
    const reports = await prisma.deviceReport.findMany({
      where: {
        deviceFamilyId: deviceFamilyId || undefined,
        lastVerdict: {
          path: ["isTrusted"],
          equals: false
        }
      },
      orderBy: { lastSeen: "desc" }
    });
    reply.send(reports);
  });
}
