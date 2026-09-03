type CacheEntry<T> = { value: T; fetchedAt: number };

export const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * A tiny in-memory TTL cache for the registry/root/status HTTP fetches
 * verifyDeviceAttestation() makes. On a fetch failure it serves a stale
 * entry (with a console.warn) rather than hard-failing -- a transient
 * registry hiccup shouldn't turn into a verification outage for every
 * integrator at once, which would defeat the point of decentralized
 * verification. It only hard-fails when there's no cached value at all yet.
 * This mirrors the existing stale-cache fallback in the backend's own
 * services/attestationAuthorities.ts.
 */
export class AttestationCache {
  private store = new Map<string, CacheEntry<unknown>>();

  constructor(private ttlMs: number = DEFAULT_CACHE_TTL_MS) {}

  async getOrFetch<T>(key: string, fetcher: () => Promise<T>): Promise<T> {
    const cached = this.store.get(key) as CacheEntry<T> | undefined;
    const isFresh = cached !== undefined && Date.now() - cached.fetchedAt < this.ttlMs;
    if (isFresh) {
      return cached.value;
    }
    try {
      const value = await fetcher();
      this.store.set(key, { value, fetchedAt: Date.now() });
      return value;
    } catch (err) {
      if (cached) {
        console.warn(
          `[ua-attestation-verifier] serving stale cache for "${key}" after fetch failure: ${(err as Error).message}`
        );
        return cached.value;
      }
      throw err;
    }
  }
}

export function createAttestationCache(ttlMs?: number): AttestationCache {
  return new AttestationCache(ttlMs);
}
