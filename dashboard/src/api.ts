export type Auth = { kind: "api-key" | "bearer"; token: string };
export type Finding = {
  finding_id: string; rule_id: string; title: string; severity: string;
  action: string; enforcement_status: string; review_status: string; created_at: string;
};
export type Policy = {
  version: number; mode: "detection_only" | "blocking"; minimum_severity: string;
  block_severity: string; action_map: Record<string, string>;
  boundary_action_map: Record<string, Record<string, string>>;
  enabled_rule_ids: string[]; excluded_rule_ids: string[];
};

const base = import.meta.env.VITE_API_BASE ?? "";

export async function api<T>(path: string, auth: Auth, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set(auth.kind === "bearer" ? "Authorization" : "X-API-Key",
    auth.kind === "bearer" ? `Bearer ${auth.token}` : auth.token);
  if (init?.body) headers.set("Content-Type", "application/json");
  const response = await fetch(`${base}${path}`, { ...init, headers });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
  return response.json() as Promise<T>;
}
