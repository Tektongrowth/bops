import "server-only";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer, type ServerResponse } from "node:http";
import { createRemoteJWKSet, jwtVerify } from "jose";
import OpenAI from "openai";
import type { ResponseInput } from "openai/resources/responses/responses";
import { getSecret, setSecret } from "./keychain";
import { stateUser } from "./store";

const issuer = "https://auth.openai.com";
const resource = "https://api.openai.com/v1";
const directScope = "chatgpt.tokens.use.direct";
const keys = createRemoteJWKSet(new URL("/.well-known/jwks.json", issuer));
export const planMode = () => process.env.BOPS_SELF_HOSTED === "1" && process.env.NEXT_PUBLIC_BOPS_CHATGPT_OAUTH === "1";

type Registration = { clientId: string; subject: string; email?: string; access?: string; refresh?: string; expires?: number };
type Accounts = { active?: string; registrations: Registration[] };
type Tokens = { id_token?: string; scope?: string; access_token?: string; refresh_token?: string; expires_in?: number };
const runtime = globalThis as typeof globalThis & { bopsPlanLocks?: Map<string, Promise<unknown>> };
const locks = runtime.bopsPlanLocks ??= new Map();
async function serialized<T>(key: string, work: () => Promise<T>): Promise<T> {
  const result = (locks.get(key) ?? Promise.resolve()).catch(() => {}).then(work);
  locks.set(key, result);
  try { return await result; } finally { if (locks.get(key) === result) locks.delete(key); }
}
async function save(key: string, value: string) {
  try { await setSecret(key, value); } catch { throw new Error("Could not save the ChatGPT connection in the Mac Keychain."); }
}
function ownerKey() {
  const user = stateUser();
  if (!planMode() || !user) throw new Error("Sign in to your local Bops workspace first.");
  return "chatgpt-plan:" + user;
}
async function records(key: string): Promise<Accounts> {
  const raw = await getSecret(key);
  return raw ? JSON.parse(raw) : { registrations: [] };
}
export async function planStatus() {
  const { active, registrations } = await records(ownerKey());
  return { active, accounts: registrations.map(({ clientId, email }) => ({ clientId, email })) };
}
async function hostId() {
  return serialized("host", async () => {
    const saved = await getSecret("chatgpt-plan-host");
    if (saved) return saved;
    const id = "urn:uuid:" + randomUUID();
    await save("chatgpt-plan-host", id);
    return id;
  });
}
async function exchange(fields: Record<string, string>): Promise<Tokens> {
  const res = await fetch(issuer + "/api/accounts/oauth/token", {
    method: "POST", body: new URLSearchParams({ ...fields, resource }), signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error("ChatGPT authorization failed (" + res.status + "). Reconnect from Bops.");
  return res.json();
}
function credentials(tokens: Tokens, oldRefresh?: string) {
  if (!tokens.access_token || !Number.isFinite(tokens.expires_in) || (tokens.expires_in ?? 0) <= 0)
    throw new Error("ChatGPT did not return usable credentials.");
  return { access: tokens.access_token, refresh: tokens.refresh_token ?? oldRefresh, expires: Date.now() + tokens.expires_in! * 1000 };
}

export async function startPlan(origin: string, existing?: string) {
  const key = ownerKey();
  const { registrations } = await records(key);
  const prior = registrations.find(x => x.clientId === existing);
  if (existing && !prior) throw new Error("Unknown account.");
  const host = await hostId();
  const state = randomBytes(32).toString("base64url");
  const nonce = randomBytes(32).toString("base64url");
  const verifier = randomBytes(48).toString("base64url");
  let used = false;
  let redirect = "";
  // Dedicated loopback callback keeps authorization codes out of Next request logs.
  const server = createServer(async (req, res: ServerResponse) => {
    const callback = new URL(req.url ?? "/", "http://127.0.0.1");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    if (req.method !== "GET" || callback.pathname !== "/auth/callback" || callback.searchParams.get("state") !== state || used) {
      res.writeHead(400).end("Invalid callback."); return;
    }
    used = true;
    server.close();
    try {
      if (ownerKey() !== key) throw new Error("The local workspace changed. Start sign-in again.");
      const p = callback.searchParams;
      if (p.has("error")) throw new Error("ChatGPT authorization was declined or did not finish.");
      const clientId = p.get("client_id") ?? prior?.clientId;
      const code = p.get("code");
      if (!clientId || clientId === "dynamic_agent_client" || (prior && prior.clientId !== clientId) || !code)
        throw new Error("ChatGPT registration was incomplete.");
      const t = await exchange({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: redirect });
      const { payload } = await jwtVerify(t.id_token ?? "", keys, { issuer, audience: clientId, algorithms: ["RS256"], requiredClaims: ["exp", "sub", "nonce"] });
      if (!payload.sub || payload.nonce !== nonce || (prior && prior.subject !== payload.sub)) throw new Error("ChatGPT identity validation failed.");
      if (!t.scope?.split(/\s+/).includes(directScope)) throw new Error("ChatGPT plan use was not authorized.");
      const account = { clientId, subject: payload.sub, email: typeof payload.email === "string" ? payload.email : undefined, ...credentials(t) };
      await serialized(key, async () => {
        const db = await records(key);
        if (db.registrations.some(x => x.clientId === clientId && x.subject !== account.subject)) throw new Error("Account identity changed.");
        db.registrations = db.registrations.filter(x => x.clientId !== clientId).concat(account);
        db.active = clientId;
        await save(key, JSON.stringify(db));
      });
      res.writeHead(303, { Location: origin + "/api/chatgpt" }).end();
    } catch (e) {
      res.writeHead(400).end("Connection failed. " + (e instanceof Error ? e.message : "Please retry."));
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const timer = setTimeout(() => server.close(), 15 * 60_000);
  timer.unref();
  server.on("close", () => clearTimeout(timer));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Callback listener unavailable.");
  redirect = "http://127.0.0.1:" + address.port + "/auth/callback";
  const u = new URL("/api/accounts/authorize", issuer);
  u.search = new URLSearchParams({
    client_id: prior?.clientId ?? "dynamic_agent_client", ...(prior ? {} : { agent_name_hint: "Bops" }),
    ext_agent_host_id: host, response_type: "code", redirect_uri: redirect,
    scope: "openid profile email offline_access resource.invoke " + directScope, resource,
    state, nonce, code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  }).toString();
  return u.href;
}

export async function disconnectPlan() {
  const key = ownerKey();
  return serialized(key, async () => {
    const db = await records(key);
    const a = db.registrations.find(x => x.clientId === db.active);
    if (!a) return true;
    let revoked = true;
    if (a.refresh) {
      const body = new URLSearchParams({ client_id: a.clientId, token: a.refresh, token_type_hint: "refresh_token" });
      revoked = await fetch(issuer + "/api/accounts/oauth/revoke", { method: "POST", body, signal: AbortSignal.timeout(10000) }).then(r => r.ok, () => false);
    }
    delete a.access; delete a.refresh; delete a.expires; delete db.active;
    await save(key, JSON.stringify(db));
    return revoked;
  });
}
async function accessToken() {
  const key = ownerKey();
  return serialized(key, async () => {
    const db = await records(key);
    const a = db.registrations.find(x => x.clientId === db.active);
    if (!a?.access) throw new Error("Connect ChatGPT in Bops Settings → Self-hosting.");
    if ((a.expires ?? 0) < Date.now() + 60_000) {
      if (!a.refresh) throw new Error("Reconnect ChatGPT in Settings.");
      const tokens = await exchange({ grant_type: "refresh_token", client_id: a.clientId, refresh_token: a.refresh });
      if (tokens.scope && !tokens.scope.split(/\s+/).includes(directScope)) throw new Error("ChatGPT plan permission expired.");
      Object.assign(a, credentials(tokens, a.refresh));
      await save(key, JSON.stringify(db));
    }
    return a.access;
  });
}
export async function planAnswer(input: ResponseInput, botName: string) {
  const api = new OpenAI({ apiKey: await accessToken(), baseURL: resource, maxRetries: 0, timeout: 90000 });
  const events = await api.responses.create({
    model: process.env.BOPS_CHAT_MODEL || "gpt-6.1-sol", input, stream: true, store: false,
    instructions: "You are " + botName + ", a Bops assistant. In this pilot you can chat and search the web. You cannot perform computer tasks, edit apps or schedule work. Be clear when a request requires those capabilities.",
    tools: [{ type: "web_search" }],
  });
  let text = "";
  for await (const e of events) {
    if (e.type === "response.output_text.delta") text += e.delta;
    if (e.type === "response.completed" && text.trim()) return text.trim();
    if (e.type === "response.failed") throw new Error(e.response.error?.message ?? "ChatGPT declined the request.");
    if (e.type === "error") throw new Error(e.message);
    if (e.type === "response.incomplete") throw new Error("ChatGPT returned an incomplete answer.");
  }
  throw new Error("ChatGPT did not complete its answer.");
}
