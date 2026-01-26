import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import appRoutes from "../src/routes/app";

const mockPrisma = {
  app: { findUnique: vi.fn() },
  federationBackend: { findFirst: vi.fn() }
};

vi.mock("../src/lib/prisma", () => ({
  getPrisma: () => mockPrisma
}));

vi.mock("../src/services/apiSecrets", () => ({
  verifyApiSecret: vi.fn(() => ({ projectId: "com.example.app" }))
}));

vi.mock("../src/lib/crypto", () => ({
  verifyIntegrityToken: vi.fn(() => ({ payload: { iss: "backend" } }))
}));

function buildApp() {
  const app = Fastify();
  app.decorate("config", {
    backendId: "backend",
    configPath: "config.yaml",
    signingKeys: {
      activeKid: "k1",
      keys: [
        {
          kid: "k1",
          alg: "EdDSA",
          privateKey: "MC4CAQAwBQYDK2VwBCIEIHZpmqe4EtA0jQE3mUYxPRRJRGgBTQhji+GkGU/Mymob",
          publicKey: "MCowBQYDK2VwAyEAwDqa+NOeBFlf79vbtbzh7N+58zMqC/4/TZKtNKZ9y3o="
        }
      ]
    },
    security: {
      apiSecretHeader: "x-ua-api-secret",
      jwt: { accessTtlMinutes: 15, refreshTtlDays: 30 }
    }
  });
  app.register(appRoutes, { prefix: "/api/v1/app" });
  return app;
}

describe("/api/v1/app/decodeToken", () => {
  it("returns APP_NOT_FOUND when projectId is not registered", async () => {
    mockPrisma.app.findUnique.mockResolvedValue(null);
    const app = buildApp();
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/app/decodeToken",
      headers: { "x-ua-api-secret": "secret" },
      payload: {
        projectId: "com.example.app",
        token: "token"
      }
    });

    expect(response.statusCode).toBe(404);
    expect(response.json().code).toBe("APP_NOT_FOUND");
  });
});
