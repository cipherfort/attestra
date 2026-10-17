// SPDX-License-Identifier: Apache-2.0
// API client. Two sign-in modes, reported by the API in /users/me (`auth_mode`):
// * oidc (production): the BFF session cookie (HttpOnly, set by /auth/callback) carries identity; no token is ever in
//   the browser. Writes send the session's CSRF token as X-AAP-CSRF. A 401 sends the user to /auth/login.
// * dev: identity comes from the persona switcher (X-AAP-Dev-User, refused by the API in production).
//
import type { components } from "./api-types";

// Types mirror what the implemented API returns. Known gap: response shapes drift from schemas/api/openapi.yaml in
// places; aligning them and switching to generated types is backlog item E16-F01-S02.

export type ControlStateValue =
  | "satisfied" | "partial" | "not_satisfied" | "stale" | "no_evidence" | "excepted" | "not_applicable" | "error";
export type Priority = "P1" | "P2" | "P3" | "P4";

export interface AppSummary {
  id: string; app_key: string; name: string; tier: number | null; lifecycle: string; exposure: string | null;
  org_unit: string; mandatory_controls: Partial<Record<ControlStateValue, number>> | null;
  open_findings: Partial<Record<Priority | "unscored", number>> | null; sla_breaches: number;
}
export interface AppDetail extends AppSummary {
  description: string; data_classification: string; personal_data: string;
  business_owner: string | null; technical_owner: string | null; champion: string | null;
}
export interface Classification {
  computed_tier: number; explanation: string; asvs_target: string;
  decision: "pending" | "approved" | "auto_approved" | "rejected"; decided_by: string | null; decided_at: string | null;
  requested_by: string | null; can_decide: boolean;
  matched_floor_rules: string[]; points: number; contributions: [string, string, number][];
}
export interface ControlItem {
  control_key: string; title: string; domain: string; objective_type: string; mode: string;
  requirement: "mandatory" | "recommended" | "n/a"; state: ControlStateValue; observe_mode: boolean;
  scope: { type: string; ref: string }; since: string; explanation: string; evidence_ids: string[];
  evaluator: string; proof: string;
}
export interface Evidence {
  id: string; type: string; confidence: string; confidence_reasons: string[]; result: string; observed_at: string;
  ingested_at: string; state: string; valid_until: string | null; producer_type: string; producer_ref: string;
  tool: string | null; tool_version: string | null; subject: Record<string, unknown>; summary: Record<string, unknown>;
  scope_ref: string; record_hash?: string; prev_hash?: string | null; raw_sha256?: string[] | null;
  run_ref?: Record<string, unknown> | null; validity_events?: { state: string; reason: string; at: string }[];
  used_by_evaluations?: string[];
}
export interface Finding {
  id: string; application_id: string; app_key: string; application_name: string; type: string; source_system: string;
  title: string; cwe_id: number | null; vulnerability: string | null; tool_severity: string | null;
  priority: Priority | null; risk_score: number | null; status: string; first_seen_at: string; last_seen_at: string;
  triage_due_at: string | null; sla_due_at: string | null; sla_breached: boolean; control_key: string | null;
  location: Record<string, unknown>; scope_ref: string;
}
export interface FindingDetail extends Finding {
  description: string; closure_evidence_id: string | null; last_seen_evidence_id: string | null;
  likelihood: number | null; impact: number | null; risk_explanation: string | null; applied_rules: string[] | null;
}
export interface FindingEvent {
  at: string; event_type: string; from_status: string | null; to_status: string | null; actor_type: string;
  actor_id: string; evidence_id: string | null; details: Record<string, unknown>;
}
export interface MaturityPractice {
  item: string; name: string; score: number; target: number | null;
  provenance: { automated: number; manual_independent: number; manual_self: number; unassessed: number };
}
export interface Maturity {
  overall: number; meets_tier_target: boolean | null; practices: MaturityPractice[];
  functions: { item: string; name: string; score: number }[]; methodology_version: string; catalogue_version: string;
}
export interface Impact {
  vulnerability: { vuln_key: string; aliases: string[]; title: string; cvss_v3_score: string | number | null;
    epss_percentile: string | number | null; in_kev: boolean };
  affected: { application: { id: string; app_key: string; name: string; tier: number; exposure: string };
    components: { purl: string; fixed_versions: string[]; scope: string }[] }[];
  possibly_affected: { application: { id: string; app_key: string; name: string; tier: number }; reason: string }[];
  not_affected_count: number;
}
export interface Scorecard {
  applications: number; mandatory_states: number; satisfied: number; missing_or_stale: number; p1_open: number;
  p1_overdue: number; kev_internet_exposed_open: number; evidence_rejections: number;
  mandatory_control_coverage_pct: number | null;
}
export interface Me { user: { id: string; display_name: string }; roles: { role: string }[]; org_wide: boolean;
  permissions: string[]; csrf_token: string | null; auth_mode: "dev" | "oidc" }
export interface Integration {
  key: string; name: string; kind: string; source: string; purpose: string; configured: boolean; missing: string[]; bootstrap: string;
  evidence: string[]; interval: string | null;
  last_run: { status: "running" | "ok" | "partial" | "failed"; started_at: string; finished_at: string | null;
    items: number; gaps: Record<string, unknown>; error: string | null } | null;
}


type Schemas = components["schemas"];
/** Generated from schemas/api/openapi.yaml (src/api-types.ts): the contract is the source of these shapes. */
export type SecurityException = Schemas["SecurityException"];
export type ExceptionEvent = SecurityException["events"][number];
export type Assessment = Schemas["Assessment"];
export type Registered = Schemas["Registered"];
export type RegisterRequest = Schemas["RegisterApplication"];
export interface ExceptionRow {
  id: string; exception_key: string; target_type: string; target_ref: string; residual_priority: Priority; status: string;
  expires_at: string | null; created_at: string; app_key: string; application_name: string; requested_by: string;
}
export interface ExceptionCreate {
  application: string; target_type: "control" | "finding" | "requirement" | "sla"; target_ref: string;
  justification: string; risk_description: string; residual_priority: Priority; compensating_controls?: string;
  remediation_plan: string; requested_expiry?: string;
}
export interface AssessmentRow {
  id: string; type: string; status: string; due_at: string | null; approved_at: string | null; app_key: string;
  application_name: string; lead_assessor: string | null; confidence: string | null;
}
export interface OrgUnit {
  id: string; slug: string; name: string; unit_type: string; parent: string | null; scm_group: string | null;
  idp_group_id: string | null; members: number; applications: number;
}
export interface AdminUser { id: string; display_name: string; email: string | null; logins: string[] }
export interface Grant {
  id: string; principal_type: string; principal_id: string; role: string; org_unit: string | null; granted_at: string;
  expires_at: string | null; principal_name: string | null; granted_by: string | null;
}

export class ApiError extends Error {
  constructor(public status: number, public title: string, public detail?: string) {
    super(detail ?? title);
  }
}

const PERSONA_KEY = "aap.persona";

export function getPersona(): string {
  try {
    return localStorage.getItem(PERSONA_KEY) ?? "ajones";
  } catch {
    return "ajones";
  }
}

export function setPersona(login: string): void {
  try {
    localStorage.setItem(PERSONA_KEY, login);
  } catch {
    /* storage unavailable: persona lasts for this page only */
  }
}

let session: { mode?: "dev" | "oidc"; csrf: string | null } = { csrf: null };

export function rememberSession(me: Me): void {
  session = { mode: me.auth_mode, csrf: me.csrf_token };
}

const SIGN_IN_REQUIRED = new Set(["sign in required", "session expired"]);

async function request<T>(path: string, init: RequestInit = {}): Promise<{ data: T; etag: string | null }> {
  const headers: Record<string, string> = { Accept: "application/json", ...(init.headers as Record<string, string> ?? {}) };
  if (session.mode !== "oidc") headers["X-AAP-Dev-User"] = getPersona();
  if (session.csrf && init.method && init.method !== "GET") headers["X-AAP-CSRF"] = session.csrf;
  const res = await fetch(`/api/v1${path}`, { ...init, headers, credentials: "same-origin" });
  if (!res.ok) {
    let title = res.statusText, detail: string | undefined;
    try {
      const p = await res.json();
      title = p.title ?? title;
      detail = p.detail;
    } catch { /* non-JSON error body */ }
    if (res.status === 401 && detail && SIGN_IN_REQUIRED.has(detail)) {
      const back = window.location.pathname + window.location.hash;
      window.location.assign(`/auth/login?return_to=${encodeURIComponent(back)}`);
    }
    throw new ApiError(res.status, title, detail);
  }
  return { data: (await res.json()) as T, etag: res.headers.get("ETag") };
}

export async function signOut(): Promise<void> {
  const res = await fetch("/auth/logout", { method: "POST", headers: { "X-AAP-CSRF": session.csrf ?? "" }, credentials: "same-origin" });
  const body = res.ok ? await res.json() : {};
  window.location.assign(body.end_session_url ?? "/");
}

export const api = {
  me: () => request<Me>("/users/me").then((r) => { rememberSession(r.data); return r.data; }),
  integrations: () => request<{ items: Integration[]; load_errors: Record<string, string> }>("/integrations").then((r) => r.data),
  applications: () => request<{ items: AppSummary[] }>("/applications").then((r) => r.data.items),
  application: (id: string) => request<AppDetail>(`/applications/${id}`).then((r) => r.data),
  classification: (id: string) => request<Classification>(`/applications/${id}/classification`).then((r) => r.data),
  register: (body: RegisterRequest) =>
    request<Registered>("/applications", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }).then((r) => r.data),
  decideClassification: (id: string, decision: "approved" | "rejected", reason: string) =>
    request<{ decision: string; tier: number }>(`/applications/${id}/classification/decisions`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision, reason }),
    }).then((r) => r.data),
  controls: (id: string) =>
    request<{ items: ControlItem[]; data_as_of: { computed_at: string } }>(`/applications/${id}/controls`).then((r) => r.data),
  maturity: (id: string) => request<Maturity>(`/applications/${id}/maturity`).then((r) => r.data),
  findings: (appId: string) =>
    request<{ items: Finding[] }>(`/findings?application=${encodeURIComponent(appId)}&status=open`).then((r) => r.data.items),
  finding: (id: string) => request<FindingDetail>(`/findings/${id}`),
  findingEvents: (id: string) => request<{ items: FindingEvent[] }>(`/findings/${id}/events`).then((r) => r.data.items),
  transition: (id: string, etag: string, action: string, comment?: string) =>
    request<FindingDetail>(`/findings/${id}/transitions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "If-Match": etag },
      body: JSON.stringify({ action, comment }),
    }).then((r) => r.data),
  evidence: (id: string) => request<Evidence>(`/evidence/${id}`).then((r) => r.data),
  impact: (vuln: string) =>
    request<Impact>(`/vulnerabilities/${encodeURIComponent(vuln)}/affected-applications`).then((r) => r.data),
  scorecard: () => request<Scorecard>("/reports/org-scorecard").then((r) => r.data),
  exceptions: (application?: string) =>
    request<{ items: ExceptionRow[] }>(`/exceptions${application ? `?application=${encodeURIComponent(application)}` : ""}`)
      .then((r) => r.data.items),
  exception: (id: string) => request<SecurityException>(`/exceptions/${encodeURIComponent(id)}`).then((r) => r.data),
  createException: (body: ExceptionCreate) => post<SecurityException>("/exceptions", body),
  exceptionAction: (id: string, action: "submit" | "cosign" | "decision" | "revoke" | "renewals", body?: unknown) =>
    post<SecurityException>(`/exceptions/${encodeURIComponent(id)}/${action}`, body),
  assessments: (application?: string) =>
    request<{ items: AssessmentRow[] }>(`/assessments${application ? `?application=${encodeURIComponent(application)}` : ""}`)
      .then((r) => r.data.items),
  assessment: (id: string) => request<Assessment>(`/assessments/${id}`).then((r) => r.data),
  createAssessment: (body: { type: string; application: string; scope?: Record<string, unknown> }) =>
    post<Assessment>("/assessments", body),
  recordAssessment: (id: string, scope: Record<string, unknown>) =>
    request<Assessment>(`/assessments/${id}/answers`, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(scope),
    }).then((r) => r.data),
  assessmentAction: (id: string, action: "submit" | "decision", body?: unknown) =>
    post<Assessment>(`/assessments/${id}/${action}`, body),
  orgUnits: () => request<{ items: OrgUnit[]; levels: string[] }>("/admin/org-units").then((r) => r.data),
  createOrgUnit: (body: { slug: string; name: string; unit_type: string; parent: string }) => post("/admin/org-units", body),
  members: (slug: string) =>
    request<{ items: { user_id: string; display_name: string; source: string }[] }>(`/admin/org-units/${slug}/members`)
      .then((r) => r.data.items),
  setMember: (slug: string, userId: string, present: boolean) =>
    request(`/admin/org-units/${slug}/members/${userId}`, { method: present ? "PUT" : "DELETE" }).then((r) => r.data),
  users: (q: string) => request<{ items: AdminUser[] }>(`/admin/users?q=${encodeURIComponent(q)}`).then((r) => r.data.items),
  grants: () => request<{ items: Grant[] }>("/admin/role-assignments").then((r) => r.data.items),
  grant: (body: { principal_type: string; principal_id: string; role: string; org_unit?: string }) =>
    post<{ id: string }>("/admin/role-assignments", body),
  revokeGrant: (id: string) => request(`/admin/role-assignments/${id}`, { method: "DELETE" }).then((r) => r.data),
  download: (report: "findings" | "controls") => download(`/reports/${report}.csv`, `aap-${report}.csv`),
};

function post<T = unknown>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body),
  }).then((r) => r.data);
}

/** Authenticated download (the dev persona header and the CSRF/session rules apply, so a plain link would not). */
async function download(path: string, filename: string): Promise<void> {
  const headers: Record<string, string> = {};
  if (session.mode !== "oidc") headers["X-AAP-Dev-User"] = getPersona();
  const res = await fetch(`/api/v1${path}`, { headers, credentials: "same-origin" });
  if (!res.ok) throw new ApiError(res.status, res.statusText);
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}
