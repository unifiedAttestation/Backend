import Link from "next/link";
import { useEffect, useState } from "react";

function decodeRole(): string | null {
  if (typeof window === "undefined") return null;
  const token = localStorage.getItem("ua_access");
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    return payload.role || null;
  } catch {
    return null;
  }
}

export default function Layout({ children }: { children: React.ReactNode }) {
  const [role, setRole] = useState<string | null>(null);

  useEffect(() => {
    setRole(decodeRole());
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-sand via-white to-sand">
      <header className="px-8 py-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Unified Attestation Portal</h1>
        <nav className="flex gap-4 text-sm">
          {(role === "app_dev" || role === "admin") && (
            <Link href="/dashboard" className="hover:text-clay">
              App Dev
            </Link>
          )}
          {(role === "oem" || role === "admin") && (
            <Link href="/oem" className="hover:text-clay">
              OEM
            </Link>
          )}
          {role === "admin" && (
            <Link href="/admin" className="hover:text-clay">
              Admin
            </Link>
          )}
        </nav>
      </header>
      <main className="px-8 pb-16">{children}</main>
    </div>
  );
}
