import type { AttestationCache } from "./cache";
import type { BackendInfo, DeviceRegistryEntry, FederationBackendEntry, RevocationStatus } from "./types";

/** Matches Server-SDK-JS's `baseUrl` convention: the backend's root URL
 * (e.g. "https://uattest.volla.tech"), NOT including "/api/v1". */
export function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
}

export async function fetchDeviceEntry(
  baseUrl: string,
  slug: string,
  cache: AttestationCache
): Promise<DeviceRegistryEntry> {
  const url = `${normalizeBaseUrl(baseUrl)}/api/v1/devices/${encodeURIComponent(slug)}`;
  return cache.getOrFetch(`device:${url}`, async () => {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Device registry lookup failed: ${res.status}`);
    }
    return (await res.json()) as DeviceRegistryEntry;
  });
}

export async function fetchRootCertificates(
  rootCertificatesUrl: string,
  cache: AttestationCache
): Promise<string[]> {
  return cache.getOrFetch(`root:${rootCertificatesUrl}`, async () => {
    const res = await fetch(rootCertificatesUrl);
    if (!res.ok) {
      throw new Error(`Root certificate fetch failed: ${res.status}`);
    }
    const data = (await res.json()) as string[];
    return Array.isArray(data) ? data : [];
  });
}

export async function fetchRevocationStatus(
  baseUrl: string,
  cache: AttestationCache
): Promise<RevocationStatus> {
  const url = `${normalizeBaseUrl(baseUrl)}/api/v1/info/status`;
  return cache.getOrFetch(`status:${url}`, async () => {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Revocation status fetch failed: ${res.status}`);
    }
    const data = (await res.json()) as { entries?: RevocationStatus };
    return data.entries || {};
  });
}

export async function fetchBackendInfo(baseUrl: string, cache: AttestationCache): Promise<BackendInfo> {
  const url = `${normalizeBaseUrl(baseUrl)}/api/v1/info`;
  return cache.getOrFetch(`info:${url}`, async () => {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Backend info fetch failed: ${res.status}`);
    }
    return (await res.json()) as BackendInfo;
  });
}

export async function fetchFederationBackends(
  baseUrl: string,
  cache: AttestationCache
): Promise<FederationBackendEntry[]> {
  const url = `${normalizeBaseUrl(baseUrl)}/api/v1/federation/backends`;
  return cache.getOrFetch(`federation:${url}`, async () => {
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`Federation backends fetch failed: ${res.status}`);
    }
    const data = (await res.json()) as FederationBackendEntry[];
    return Array.isArray(data) ? data : [];
  });
}
