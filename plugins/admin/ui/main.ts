// Admin page for the registry: decide access requests, add and revoke
// grants, read the audit log. It is served from `<mount>/ui/` and calls the
// admin router at `<mount>/` with the administrator's bearer token, kept in
// sessionStorage for this tab only. Everything shown is built with DOM
// nodes and text, never HTML strings, since requests carry applicant input.

import type { AccessRequest, AuditEvent, Grant, Permission, RequestStatus } from "../src/types.js";
import "./style.css";

const API = new URL("../", location.href);
const TOKEN_KEY = "cawg-trqp-admin-token";

class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

let token: string | null = readToken();

function readToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function storeToken(value: string | null): void {
  token = value;
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Storage blocked: the token lasts until the page reloads.
  }
}

async function api<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(new URL(path, API), {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = (await res.json().catch(() => null)) as { detail?: string } | null;
  if (!res.ok) throw new ApiError(res.status, data?.detail ?? `${res.status} ${res.statusText}`);
  return data as T;
}

type Child = Node | string | null | undefined | false;
type Attrs = Record<string, string | boolean | ((event: Event) => void)>;

function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (typeof value === "function") el.addEventListener(name.slice(2), value);
    else if (value === true) el.setAttribute(name, "");
    else if (value !== false) el.setAttribute(name, value);
  }
  for (const child of children) if (child) el.append(child);
  return el;
}

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "");
const newestFirst = <T>(items: T[], key: (item: T) => string) => [...items].sort((a, b) => key(b).localeCompare(key(a)));

const evidenceList = (evidence: string[]) => evidence.length > 0 && h("ul", { class: "evidence" }, ...evidence.map((e) => h("li", {}, e)));

function permission(p: Permission): HTMLElement {
  return h("div", { class: "perm" }, h("strong", {}, p.action), " · ", p.resource, h("div", { class: "muted mono" }, p.authority_id));
}

const app = document.getElementById("app")!;
const flash = h("p", { class: "flash", role: "status" });

function say(message: string, error = false): void {
  flash.textContent = message;
  flash.className = error ? "flash error" : "flash";
}

/** Runs an action from a button, reporting failure, then re-renders. */
async function act(button: HTMLButtonElement, fn: () => Promise<string>): Promise<void> {
  button.disabled = true;
  try {
    say(await fn());
  } catch (err) {
    say((err as Error).message, true);
  }
  await renderView();
}

// ---- Sign in --------------------------------------------------------------

function signIn(): HTMLElement {
  const input = h("input", { type: "password", name: "token", autocomplete: "current-password", required: true, placeholder: "Admin token" });
  const error = h("p", { class: "flash error" });
  return h(
    "form",
    {
      class: "card signin",
      onsubmit: async (event) => {
        event.preventDefault();
        storeToken(input.value.trim());
        try {
          await api("admin/requests?status=pending");
          render();
        } catch (err) {
          storeToken(null);
          error.textContent = err instanceof ApiError && err.status === 401 ? "That token isn't an administrator's." : (err as Error).message;
        }
      },
    },
    h("h1", {}, "Registry admin"),
    h("p", { class: "muted" }, "Sign in with an administrator token. It is kept for this tab only."),
    h("label", {}, "Token", input),
    h("button", { type: "submit" }, "Sign in"),
    error,
  );
}

// ---- Requests -------------------------------------------------------------

async function requestsView(): Promise<HTMLElement> {
  const status = (new URLSearchParams(location.hash.split("?")[1]).get("status") ?? "pending") as RequestStatus | "all";
  const query = status === "all" ? "" : `?status=${status}`;
  const requests = newestFirst(await api<AccessRequest[]>(`admin/requests${query}`), (r) => r.created_at);

  const filter = h(
    "select",
    { onchange: (e) => (location.hash = `#requests?status=${(e.target as HTMLSelectElement).value}`) },
    ...["pending", "approved", "rejected", "all"].map((s) => h("option", { value: s, selected: s === status }, s)),
  );

  const rows = requests.map((r) => {
    const note = h("input", { type: "text", placeholder: "Note (optional)" });
    const decide = (decision: "approve" | "reject") => (e: Event) =>
      act(e.currentTarget as HTMLButtonElement, async () => {
        await api(`admin/requests/${encodeURIComponent(r.id)}/${decision}`, { note: note.value || undefined });
        return `${decision === "approve" ? "Approved" : "Rejected"} ${r.entity_id}`;
      });
    const a = r.applicant;
    return h(
      "tr",
      {},
      h("td", {}, when(r.created_at)),
      h("td", { class: "mono wrap" }, r.entity_id),
      h("td", {}, permission(r)),
      h(
        "td",
        {},
        h("div", {}, [a.name, a.organization].filter(Boolean).join(", ")),
        a.email && h("div", { class: "muted" }, a.email),
        a.note && h("div", { class: "muted" }, `“${a.note}”`),
        evidenceList(r.evidence),
      ),
      h(
        "td",
        {},
        r.status === "pending"
          ? h("div", { class: "decide" }, note, h("button", { onclick: decide("approve") }, "Approve"), h("button", { class: "secondary", onclick: decide("reject") }, "Reject"))
          : h(
              "div",
              {},
              h("span", { class: `badge ${r.status}` }, r.status),
              h("div", { class: "muted" }, `${r.decided_by ?? ""} ${when(r.decided_at)}`),
              r.decision_note && h("div", { class: "muted" }, `“${r.decision_note}”`),
            ),
      ),
    );
  });

  return h(
    "section",
    {},
    h("div", { class: "toolbar" }, h("h2", {}, "Access requests"), h("label", { class: "inline" }, "Show ", filter)),
    rows.length
      ? h("table", {}, h("thead", {}, h("tr", {}, ...["Received", "Entity", "Permission", "Applicant", "Decision"].map((c) => h("th", {}, c)))), h("tbody", {}, ...rows))
      : h("p", { class: "empty" }, status === "pending" ? "No requests are waiting." : "No requests."),
  );
}

// ---- Grants ---------------------------------------------------------------

function addGrantForm(requestable: Permission[]): HTMLElement {
  const field = (name: string, label: string, placeholder = "") =>
    h("label", {}, label, h("input", { name, type: "text", required: true, placeholder, autocomplete: "off" }));
  const form = h(
    "form",
    {
      class: "card grid",
      onsubmit: (event) => {
        event.preventDefault();
        const data = new FormData(form);
        const value = (k: string) => String(data.get(k) ?? "").trim();
        void act(form.querySelector("button[type=submit]")!, async () => {
          const grant = await api<Grant>("admin/grants", {
            entity_id: value("entity_id"),
            authority_id: value("authority_id"),
            action: value("action"),
            resource: value("resource"),
            evidence: value("evidence").split("\n").map((l) => l.trim()).filter(Boolean),
          });
          return `Granted ${grant.action} · ${grant.resource} to ${grant.entity_id}`;
        });
      },
    },
    h("h3", { class: "span" }, "Add a grant"),
    requestable.length > 0 &&
      h(
        "label",
        { class: "span" },
        "Permission",
        h(
          "select",
          {
            onchange: (e) => {
              const p = requestable[Number((e.target as HTMLSelectElement).value)];
              if (!p) return;
              for (const k of ["authority_id", "action", "resource"] as const) (form.elements.namedItem(k) as HTMLInputElement).value = p[k];
            },
          },
          h("option", { value: "" }, "Choose a requestable permission, or fill in below"),
          ...requestable.map((p, i) => h("option", { value: String(i) }, `${p.action} · ${p.resource} (${p.authority_id})`)),
        ),
      ),
    h("div", { class: "span" }, field("entity_id", "Entity", "did:key:z6Mk…")),
    field("authority_id", "Authority", "did:web:registry.example"),
    field("action", "Action", "issue"),
    h("div", { class: "span" }, field("resource", "Resource", "ExampleGuildLikenessConsentCredential")),
    h("label", { class: "span" }, "Evidence (one per line, optional)", h("textarea", { name: "evidence", rows: "2" })),
    h("div", { class: "span" }, h("button", { type: "submit" }, "Add grant")),
  );
  return form;
}

async function grantsView(): Promise<HTMLElement> {
  const show = new URLSearchParams(location.hash.split("?")[1]).get("show") ?? "active";
  const query = show === "all" ? "" : `?active=${show === "active"}`;
  const [grants, { requestable }] = await Promise.all([
    api<Grant[]>(`admin/grants${query}`),
    api<{ requestable: Permission[] }>("permissions"),
  ]);

  const filter = h(
    "select",
    { onchange: (e) => (location.hash = `#grants?show=${(e.target as HTMLSelectElement).value}`) },
    ...["active", "revoked", "all"].map((s) => h("option", { value: s, selected: s === show }, s)),
  );

  const rows = newestFirst(grants, (g) => g.granted_at).map((g) => {
    // `reason` is TRQP's machine reason ("revoked"); the admin's own words are kept in the evidence.
    const revocationReason = g.evidence.find((e) => e.startsWith("revocation-reason:"))?.slice("revocation-reason:".length);
    const reason = h("input", { type: "text", placeholder: "Reason (optional)" });
    const revoke = (e: Event) =>
      act(e.currentTarget as HTMLButtonElement, async () => {
        await api(`admin/grants/${encodeURIComponent(g.id)}/revoke`, { reason: reason.value || undefined });
        return `Revoked ${g.action} · ${g.resource} for ${g.entity_id}`;
      });
    return h(
      "tr",
      {},
      h("td", { class: "mono wrap" }, g.entity_id),
      h("td", {}, permission(g), evidenceList(g.evidence.filter((e) => !e.startsWith("revocation-reason:") && !e.startsWith("revoked-by:")))),
      h("td", {}, when(g.granted_at), h("div", { class: "muted" }, g.request_id ? `${g.granted_by} (request)` : g.granted_by)),
      h(
        "td",
        {},
        g.revoked_at
          ? h("div", {}, h("span", { class: "badge rejected" }, "revoked"), h("div", { class: "muted" }, `${g.revoked_by ?? ""} ${when(g.revoked_at)}`), revocationReason && h("div", { class: "muted" }, `“${revocationReason}”`))
          : h(
              "div",
              { class: "decide" },
              h("span", { class: "badge approved" }, g.expires ? `until ${when(g.expires)}` : "active"),
              reason,
              h("button", { class: "danger", onclick: revoke }, "Revoke"),
            ),
      ),
    );
  });

  return h(
    "section",
    {},
    addGrantForm(requestable),
    h("div", { class: "toolbar" }, h("h2", {}, "Grants"), h("label", { class: "inline" }, "Show ", filter)),
    rows.length
      ? h("table", {}, h("thead", {}, h("tr", {}, ...["Entity", "Permission", "Granted", "Status"].map((c) => h("th", {}, c)))), h("tbody", {}, ...rows))
      : h("p", { class: "empty" }, "No grants."),
  );
}

// ---- Audit ----------------------------------------------------------------

async function auditView(): Promise<HTMLElement> {
  const events = newestFirst(await api<AuditEvent[]>("admin/audit"), (e) => e.at);
  return h(
    "section",
    {},
    h("div", { class: "toolbar" }, h("h2", {}, "Audit log")),
    events.length
      ? h(
          "table",
          {},
          h("thead", {}, h("tr", {}, ...["When", "Who", "What", "Entity", "Detail"].map((c) => h("th", {}, c)))),
          h(
            "tbody",
            {},
            ...events.map((e) =>
              h(
                "tr",
                {},
                h("td", {}, when(e.at)),
                h("td", { class: "mono wrap" }, e.actor),
                h("td", {}, h("code", {}, e.action)),
                h("td", { class: "mono wrap" }, e.entity_id),
                h(
                  "td",
                  { class: "wrap muted" },
                  ...Object.entries(e.detail)
                    .filter(([, v]) => v !== null && v !== undefined)
                    .map(([k, v]) => h("div", {}, `${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)),
                ),
              ),
            ),
          ),
        )
      : h("p", { class: "empty" }, "Nothing has happened yet."),
  );
}

// ---- Shell ----------------------------------------------------------------

const VIEWS = { requests: ["Requests", requestsView], grants: ["Grants", grantsView], audit: ["Audit", auditView] } as const;
type ViewName = keyof typeof VIEWS;

const content = h("div", { class: "content" });

function currentView(): ViewName {
  const name = location.hash.slice(1).split("?")[0];
  return name in VIEWS ? (name as ViewName) : "requests";
}

async function renderView(): Promise<void> {
  const name = currentView();
  for (const link of app.querySelectorAll<HTMLAnchorElement>("nav a")) link.classList.toggle("active", link.dataset.view === name);
  try {
    content.replaceChildren(await VIEWS[name][1]());
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      // The token stopped working (rotated, or the admin was removed).
      storeToken(null);
      render();
      return;
    }
    content.replaceChildren(h("p", { class: "flash error" }, (err as Error).message));
  }
}

function render(): void {
  if (!token) {
    app.replaceChildren(signIn());
    return;
  }
  app.replaceChildren(
    h(
      "header",
      {},
      h("h1", {}, "Registry admin"),
      h("nav", {}, ...Object.entries(VIEWS).map(([name, [label]]) => h("a", { href: `#${name}`, "data-view": name }, label))),
      h("button", { class: "secondary", onclick: () => (storeToken(null), render()) }, "Sign out"),
    ),
    flash,
    content,
  );
  void renderView();
}

window.addEventListener("hashchange", () => {
  say("");
  if (token) void renderView();
});
render();
