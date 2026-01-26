import { useEffect, useState } from "react";
import Layout from "../components/Layout";

const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:3001";

type DeviceFamily = {
  id: string;
  name: string;
  codename?: string | null;
  model?: string | null;
  manufacturer?: string | null;
  brand?: string | null;
  trustAnchorIds: string[];
  createdAt: string;
};

type TrustAnchor = {
  id: string;
  name: string;
  pem: string;
  createdAt: string;
};

type BuildPolicy = {
  id: string;
  name: string;
  verifiedBootKeyHex: string;
  verifiedBootHashHex?: string | null;
  osVersionRaw?: number | null;
  minOsPatchLevelRaw?: number | null;
  minVendorPatchLevelRaw?: number | null;
  minBootPatchLevelRaw?: number | null;
  expectedDeviceLocked?: boolean | null;
  expectedVerifiedBootState?: string | null;
  enabled: boolean;
  createdAt: string;
};

type DeviceReport = {
  id: string;
  scopedDeviceId: string;
  issuerBackendId: string;
  lastVerdict: { isTrusted: boolean; reasonCodes: string[] };
  lastSeen: string;
  buildPolicyName?: string | null;
};

export default function OemPage() {
  const [families, setFamilies] = useState<DeviceFamily[]>([]);
  const [selectedFamily, setSelectedFamily] = useState<DeviceFamily | null>(null);
  const [activeTab, setActiveTab] = useState<"builds" | "anchors" | "reports">("builds");
  const [displayName, setDisplayName] = useState("");
  const [federationBackends, setFederationBackends] = useState<
    { id: string; backendId: string; name: string; status: string }[]
  >([]);

  const [familyForm, setFamilyForm] = useState({
    name: "",
    codename: "",
    model: "",
    manufacturer: "",
    brand: ""
  });

  const [familyEdit, setFamilyEdit] = useState({
    name: "",
    codename: "",
    model: "",
    manufacturer: "",
    brand: ""
  });

  const [trustAnchors, setTrustAnchors] = useState<TrustAnchor[]>([]);
  const [anchorName, setAnchorName] = useState("");
  const [anchorPem, setAnchorPem] = useState("");

  const [builds, setBuilds] = useState<BuildPolicy[]>([]);
  const [buildForm, setBuildForm] = useState({
    id: "",
    name: "",
    verifiedBootKeyHex: "",
    verifiedBootHashHex: "",
    osVersionRaw: "",
    minOsPatchLevelRaw: "",
    minVendorPatchLevelRaw: "",
    minBootPatchLevelRaw: "",
    expectedDeviceLocked: "",
    expectedVerifiedBootState: "",
    enabled: true
  });

  const [reports, setReports] = useState<DeviceReport[]>([]);

  const access = typeof window !== "undefined" ? localStorage.getItem("ua_access") : null;

  const loadFamilies = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/device-families`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      setFamilies(await res.json());
    }
  };

  const loadTrustAnchors = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/trust-anchors`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      setTrustAnchors(await res.json());
    }
  };

  const loadBuilds = async (familyId: string) => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/device-families/${familyId}/builds`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      setBuilds(await res.json());
    }
  };

  const loadReports = async (familyId: string) => {
    if (!access) return;
    const res = await fetch(
      `${backendUrl}/api/v1/oem/reports/failing-devices?deviceFamilyId=${familyId}`,
      {
        headers: { Authorization: `Bearer ${access}` }
      }
    );
    if (res.ok) {
      setReports(await res.json());
    }
  };

  const loadProfile = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/profile`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setDisplayName(data.displayName || "");
    }
  };

  const loadFederation = async () => {
    const res = await fetch(`${backendUrl}/api/v1/federation/backends`);
    if (res.ok) {
      setFederationBackends(await res.json());
    }
  };

  useEffect(() => {
    loadFamilies();
    loadTrustAnchors();
    loadProfile();
    loadFederation();
  }, [access]);

  const createFamily = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/device-families`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        name: familyForm.name,
        codename: familyForm.codename || undefined,
        model: familyForm.model || undefined,
        manufacturer: familyForm.manufacturer || undefined,
        brand: familyForm.brand || undefined
      })
    });
    if (res.ok) {
      setFamilyForm({ name: "", codename: "", model: "", manufacturer: "", brand: "" });
      loadFamilies();
    }
  };

  const updateFamily = async () => {
    if (!access || !selectedFamily) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/device-families/${selectedFamily.id}`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        name: familyEdit.name,
        codename: familyEdit.codename || undefined,
        model: familyEdit.model || undefined,
        manufacturer: familyEdit.manufacturer || undefined,
        brand: familyEdit.brand || undefined,
        trustAnchorIds: selectedFamily.trustAnchorIds
      })
    });
    if (res.ok) {
      const updated = await res.json();
      setSelectedFamily(updated);
      loadFamilies();
    }
  };

  const attachAnchor = async (anchorId: string, next: boolean) => {
    if (!access || !selectedFamily) return;
    const nextIds = next
      ? Array.from(new Set([...selectedFamily.trustAnchorIds, anchorId]))
      : selectedFamily.trustAnchorIds.filter((id) => id !== anchorId);
    const res = await fetch(`${backendUrl}/api/v1/oem/device-families/${selectedFamily.id}`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ trustAnchorIds: nextIds })
    });
    if (res.ok) {
      const updated = await res.json();
      setSelectedFamily(updated);
      loadFamilies();
    }
  };

  const createAnchor = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/trust-anchors`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ name: anchorName, pem: anchorPem })
    });
    if (res.ok) {
      setAnchorName("");
      setAnchorPem("");
      loadTrustAnchors();
    }
  };

  const deleteAnchor = async (anchorId: string) => {
    if (!access) return;
    await fetch(`${backendUrl}/api/v1/oem/trust-anchors/${anchorId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${access}` }
    });
    loadTrustAnchors();
    loadFamilies();
  };

  const saveBuild = async () => {
    if (!access || !selectedFamily) return;
    const payload = {
      name: buildForm.name,
      verifiedBootKeyHex: buildForm.verifiedBootKeyHex,
      verifiedBootHashHex: buildForm.verifiedBootHashHex || undefined,
      osVersionRaw: buildForm.osVersionRaw ? Number(buildForm.osVersionRaw) : undefined,
      minOsPatchLevelRaw: buildForm.minOsPatchLevelRaw
        ? Number(buildForm.minOsPatchLevelRaw)
        : undefined,
      minVendorPatchLevelRaw: buildForm.minVendorPatchLevelRaw
        ? Number(buildForm.minVendorPatchLevelRaw)
        : undefined,
      minBootPatchLevelRaw: buildForm.minBootPatchLevelRaw
        ? Number(buildForm.minBootPatchLevelRaw)
        : undefined,
      expectedDeviceLocked:
        buildForm.expectedDeviceLocked === ""
          ? undefined
          : buildForm.expectedDeviceLocked === "true",
      expectedVerifiedBootState: buildForm.expectedVerifiedBootState || undefined,
      enabled: buildForm.enabled
    };
    const isEdit = Boolean(buildForm.id);
    const url = isEdit
      ? `${backendUrl}/api/v1/oem/device-families/${selectedFamily.id}/builds/${buildForm.id}`
      : `${backendUrl}/api/v1/oem/device-families/${selectedFamily.id}/builds`;
    const method = isEdit ? "PUT" : "POST";
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      setBuildForm({
        id: "",
        name: "",
        verifiedBootKeyHex: "",
        verifiedBootHashHex: "",
        osVersionRaw: "",
        minOsPatchLevelRaw: "",
        minVendorPatchLevelRaw: "",
        minBootPatchLevelRaw: "",
        expectedDeviceLocked: "",
        expectedVerifiedBootState: "",
        enabled: true
      });
      loadBuilds(selectedFamily.id);
    }
  };

  const editBuild = (build: BuildPolicy) => {
    setBuildForm({
      id: build.id,
      name: build.name,
      verifiedBootKeyHex: build.verifiedBootKeyHex,
      verifiedBootHashHex: build.verifiedBootHashHex || "",
      osVersionRaw: build.osVersionRaw?.toString() || "",
      minOsPatchLevelRaw: build.minOsPatchLevelRaw?.toString() || "",
      minVendorPatchLevelRaw: build.minVendorPatchLevelRaw?.toString() || "",
      minBootPatchLevelRaw: build.minBootPatchLevelRaw?.toString() || "",
      expectedDeviceLocked:
        build.expectedDeviceLocked === null || build.expectedDeviceLocked === undefined
          ? ""
          : build.expectedDeviceLocked
          ? "true"
          : "false",
      expectedVerifiedBootState: build.expectedVerifiedBootState || "",
      enabled: build.enabled
    });
  };

  const deleteBuild = async (buildId: string) => {
    if (!access || !selectedFamily) return;
    await fetch(
      `${backendUrl}/api/v1/oem/device-families/${selectedFamily.id}/builds/${buildId}`,
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${access}` }
      }
    );
    loadBuilds(selectedFamily.id);
  };

  const saveProfile = async () => {
    if (!access) return;
    await fetch(`${backendUrl}/api/v1/profile`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ displayName })
    });
  };

  const selectFamily = (family: DeviceFamily) => {
    setSelectedFamily(family);
    setFamilyEdit({
      name: family.name,
      codename: family.codename || "",
      model: family.model || "",
      manufacturer: family.manufacturer || "",
      brand: family.brand || ""
    });
    setActiveTab("builds");
    loadBuilds(family.id);
    loadReports(family.id);
  };

  useEffect(() => {
    if (selectedFamily) {
      loadReports(selectedFamily.id);
    }
  }, [selectedFamily]);

  return (
    <Layout>
      <div className="grid lg:grid-cols-[2fr,1fr] gap-8">
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Device Families</h2>
          <div className="mt-4 space-y-3">
            {families.map((family) => (
              <button
                key={family.id}
                className={`w-full text-left rounded-xl border px-4 py-3 transition ${
                  selectedFamily?.id === family.id
                    ? "border-ink bg-ink text-white"
                    : "border-gray-200 bg-white"
                }`}
                onClick={() => selectFamily(family)}
              >
                <div className="font-medium">{family.name}</div>
                <div className="text-xs opacity-80">Codename: {family.codename || "-"}</div>
                <div className="text-xs opacity-80">Model: {family.model || "-"}</div>
              </button>
            ))}
          </div>
        </section>

        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Register Device Family</h2>
          <div className="mt-4 space-y-3">
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Device family name"
              value={familyForm.name}
              onChange={(e) => setFamilyForm({ ...familyForm, name: e.target.value })}
            />
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Codename (optional)"
              value={familyForm.codename}
              onChange={(e) => setFamilyForm({ ...familyForm, codename: e.target.value })}
            />
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Model (optional)"
              value={familyForm.model}
              onChange={(e) => setFamilyForm({ ...familyForm, model: e.target.value })}
            />
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Manufacturer (optional)"
              value={familyForm.manufacturer}
              onChange={(e) => setFamilyForm({ ...familyForm, manufacturer: e.target.value })}
            />
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Brand (optional)"
              value={familyForm.brand}
              onChange={(e) => setFamilyForm({ ...familyForm, brand: e.target.value })}
            />
            <button className="w-full rounded-lg bg-moss text-white py-2" onClick={createFamily}>
              Save
            </button>
          </div>
        </section>
      </div>

      {selectedFamily && (
        <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <h2 className="text-xl font-semibold">{selectedFamily.name}</h2>
              <p className="text-xs text-gray-500">ID: {selectedFamily.id}</p>
            </div>
            <div className="flex gap-2 text-sm">
              <button
                className={`rounded-full px-4 py-2 ${
                  activeTab === "builds" ? "bg-ink text-white" : "bg-white border"
                }`}
                onClick={() => setActiveTab("builds")}
              >
                Builds
              </button>
              <button
                className={`rounded-full px-4 py-2 ${
                  activeTab === "anchors" ? "bg-ink text-white" : "bg-white border"
                }`}
                onClick={() => setActiveTab("anchors")}
              >
                Trust Anchors
              </button>
              <button
                className={`rounded-full px-4 py-2 ${
                  activeTab === "reports" ? "bg-ink text-white" : "bg-white border"
                }`}
                onClick={() => setActiveTab("reports")}
              >
                Reports
              </button>
            </div>
          </div>

          <div className="mt-6 grid md:grid-cols-[1.2fr,1fr] gap-6">
            <div>
              <h3 className="text-sm font-semibold text-gray-700">Family Details</h3>
              <div className="mt-3 space-y-2">
                <input
                  className="w-full rounded-lg border border-gray-300 px-3 py-2"
                  placeholder="Name"
                  value={familyEdit.name}
                  onChange={(e) => setFamilyEdit({ ...familyEdit, name: e.target.value })}
                />
                <input
                  className="w-full rounded-lg border border-gray-300 px-3 py-2"
                  placeholder="Codename"
                  value={familyEdit.codename}
                  onChange={(e) => setFamilyEdit({ ...familyEdit, codename: e.target.value })}
                />
                <input
                  className="w-full rounded-lg border border-gray-300 px-3 py-2"
                  placeholder="Model"
                  value={familyEdit.model}
                  onChange={(e) => setFamilyEdit({ ...familyEdit, model: e.target.value })}
                />
                <input
                  className="w-full rounded-lg border border-gray-300 px-3 py-2"
                  placeholder="Manufacturer"
                  value={familyEdit.manufacturer}
                  onChange={(e) => setFamilyEdit({ ...familyEdit, manufacturer: e.target.value })}
                />
                <input
                  className="w-full rounded-lg border border-gray-300 px-3 py-2"
                  placeholder="Brand"
                  value={familyEdit.brand}
                  onChange={(e) => setFamilyEdit({ ...familyEdit, brand: e.target.value })}
                />
                <button className="rounded-lg bg-ink text-white px-4 py-2" onClick={updateFamily}>
                  Update Family
                </button>
              </div>
            </div>

            {activeTab === "builds" && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700">Build Policies</h3>
                <div className="mt-3 space-y-2">
                  <input
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Build name"
                    value={buildForm.name}
                    onChange={(e) => setBuildForm({ ...buildForm, name: e.target.value })}
                  />
                  <input
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Verified boot key hex"
                    value={buildForm.verifiedBootKeyHex}
                    onChange={(e) =>
                      setBuildForm({ ...buildForm, verifiedBootKeyHex: e.target.value })
                    }
                  />
                  <input
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Verified boot hash hex (optional)"
                    value={buildForm.verifiedBootHashHex}
                    onChange={(e) =>
                      setBuildForm({ ...buildForm, verifiedBootHashHex: e.target.value })
                    }
                  />
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      className="w-full rounded-lg border border-gray-300 px-3 py-2"
                      placeholder="OS version raw"
                      value={buildForm.osVersionRaw}
                      onChange={(e) => setBuildForm({ ...buildForm, osVersionRaw: e.target.value })}
                    />
                    <input
                      className="w-full rounded-lg border border-gray-300 px-3 py-2"
                      placeholder="Min OS patch level"
                      value={buildForm.minOsPatchLevelRaw}
                      onChange={(e) =>
                        setBuildForm({ ...buildForm, minOsPatchLevelRaw: e.target.value })
                      }
                    />
                    <input
                      className="w-full rounded-lg border border-gray-300 px-3 py-2"
                      placeholder="Min vendor patch"
                      value={buildForm.minVendorPatchLevelRaw}
                      onChange={(e) =>
                        setBuildForm({ ...buildForm, minVendorPatchLevelRaw: e.target.value })
                      }
                    />
                    <input
                      className="w-full rounded-lg border border-gray-300 px-3 py-2"
                      placeholder="Min boot patch"
                      value={buildForm.minBootPatchLevelRaw}
                      onChange={(e) =>
                        setBuildForm({ ...buildForm, minBootPatchLevelRaw: e.target.value })
                      }
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <select
                      className="w-full rounded-lg border border-gray-300 px-3 py-2"
                      value={buildForm.expectedDeviceLocked}
                      onChange={(e) =>
                        setBuildForm({ ...buildForm, expectedDeviceLocked: e.target.value })
                      }
                    >
                      <option value="">Device locked (any)</option>
                      <option value="true">Device locked: true</option>
                      <option value="false">Device locked: false</option>
                    </select>
                    <select
                      className="w-full rounded-lg border border-gray-300 px-3 py-2"
                      value={buildForm.expectedVerifiedBootState}
                      onChange={(e) =>
                        setBuildForm({
                          ...buildForm,
                          expectedVerifiedBootState: e.target.value
                        })
                      }
                    >
                      <option value="">Verified boot state (any)</option>
                      <option value="VERIFIED">VERIFIED</option>
                      <option value="UNVERIFIED">UNVERIFIED</option>
                    </select>
                  </div>
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={buildForm.enabled}
                      onChange={(e) => setBuildForm({ ...buildForm, enabled: e.target.checked })}
                    />
                    Enabled
                  </label>
                  <button className="rounded-lg bg-moss text-white px-4 py-2" onClick={saveBuild}>
                    {buildForm.id ? "Update Build" : "Add Build"}
                  </button>
                </div>

                <div className="mt-6 space-y-2">
                  {builds.map((build) => (
                    <div key={build.id} className="rounded-lg border border-gray-200 px-4 py-2">
                      <div className="font-medium">{build.name}</div>
                      <div className="text-xs text-gray-500">
                        Boot key: {build.verifiedBootKeyHex.slice(0, 16)}...
                      </div>
                      <div className="text-xs text-gray-500">Enabled: {build.enabled ? "yes" : "no"}</div>
                      <div className="mt-2 flex gap-2 text-xs">
                        <button className="rounded-md bg-sand px-3 py-1" onClick={() => editBuild(build)}>
                          Edit
                        </button>
                        <button
                          className="rounded-md bg-rose-500 text-white px-3 py-1"
                          onClick={() => deleteBuild(build.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === "anchors" && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700">Trust Anchors</h3>
                <div className="mt-3 space-y-2">
                  {trustAnchors.map((anchor) => {
                    const attached = selectedFamily.trustAnchorIds.includes(anchor.id);
                    return (
                      <label
                        key={anchor.id}
                        className="flex items-center justify-between rounded-lg border border-gray-200 px-4 py-2 text-sm"
                      >
                        <span>{anchor.name}</span>
                        <span className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={attached}
                            onChange={(e) => attachAnchor(anchor.id, e.target.checked)}
                          />
                          <button
                            className="text-xs text-red-600"
                            onClick={() => deleteAnchor(anchor.id)}
                          >
                            Delete
                          </button>
                        </span>
                      </label>
                    );
                  })}
                </div>

                <div className="mt-4 space-y-2">
                  <input
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Anchor name"
                    value={anchorName}
                    onChange={(e) => setAnchorName(e.target.value)}
                  />
                  <textarea
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Root/intermediate PEM"
                    value={anchorPem}
                    onChange={(e) => setAnchorPem(e.target.value)}
                  />
                  <button className="rounded-lg bg-clay text-white px-4 py-2" onClick={createAnchor}>
                    Upload Anchor
                  </button>
                </div>
              </div>
            )}

            {activeTab === "reports" && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700">Failing Devices</h3>
                <div className="mt-3 space-y-2">
                  {reports.map((report) => (
                    <div key={report.id} className="rounded-lg border border-gray-200 px-4 py-2">
                      <div className="text-sm">Device: {report.scopedDeviceId.slice(0, 16)}...</div>
                      <div className="text-xs text-gray-500">Last seen: {report.lastSeen}</div>
                      <div className="text-xs text-gray-500">
                        Build policy: {report.buildPolicyName || "unmatched"}
                      </div>
                      <div className="text-xs text-gray-500">
                        Reasons: {report.lastVerdict?.reasonCodes?.join(", ") || "unknown"}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
        <h2 className="text-xl font-semibold">Profile</h2>
        <div className="mt-4 flex flex-col md:flex-row gap-3">
          <input
            className="flex-1 rounded-lg border border-gray-300 px-3 py-2"
            placeholder="Display name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
          <button className="rounded-lg bg-ink text-white px-4 py-2" onClick={saveProfile}>
            Save
          </button>
        </div>
      </section>

      <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
        <h2 className="text-xl font-semibold">Federation (Read-only)</h2>
        <div className="mt-4 grid md:grid-cols-2 gap-4">
          {federationBackends.map((backend) => (
            <div key={backend.id} className="rounded-xl border border-gray-200 p-4">
              <div className="font-semibold">{backend.name}</div>
              <div className="text-xs text-gray-500">{backend.backendId}</div>
              <div className="text-xs text-gray-500">Status: {backend.status}</div>
            </div>
          ))}
        </div>
      </section>
    </Layout>
  );
}
