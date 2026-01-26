import { FastifyInstance } from "fastify";

export default async function infoRoutes(app: FastifyInstance) {
  app.get("/", async () => {
    const publicKeys = app.config.signingKeys.keys.map((key) => ({
      kid: key.kid,
      alg: key.alg,
      publicKey: key.publicKey
    }));
    return {
      backendId: app.config.backendId,
      publicKeys
    };
  });
}
