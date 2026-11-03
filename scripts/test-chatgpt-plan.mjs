// Local OAuth contract test. The browser callback is real; the issuer, model and keychain are fixtures.
import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

process.env.BOPS_SELF_HOSTED = "1";
process.env.NEXT_PUBLIC_BOPS_CHATGPT_OAUTH = "1";
const vault = new Map();
globalThis.__planVault = vault;
registerHooks({
  resolve(name, ctx, next) {
    if (ctx.parentURL?.endsWith("/chatgpt-plan.ts")) {
      if (name === "./store") return { shortCircuit: true, url: "data:text/javascript,export const stateUser=()=> 'trial'" };
      if (name === "./keychain") return { shortCircuit: true, url: "data:text/javascript,export const getSecret=k=>globalThis.__planVault.get(k);export const setSecret=(k,v)=>globalThis.__planVault.set(k,v)" };
    }
    return next(name, ctx);
  },
});
const realFetch = globalThis.fetch;
const pair = await generateKeyPair("RS256");
const publicKey = await exportJWK(pair.publicKey);
let nonce, refreshes = 0, messages = 0;
globalThis.fetch = async (input, init) => {
  const url = String(input?.url ?? input);
  if (url.startsWith("http://127.0.0.1:")) return realFetch(input, init);
  if (url === "https://auth.openai.com/.well-known/jwks.json") return Response.json({ keys: [{ ...publicKey, alg: "RS256", kid: "test" }] });
  if (url === "https://auth.openai.com/api/accounts/oauth/token") {
    assert.equal(init.body.get("client_id"), "test-client");
    if (init.body.get("grant_type") === "refresh_token") {
      refreshes++;
      return Response.json({ access_token: "fresh", refresh_token: "rotated", expires_in: 3600 });
    }
    const id = await new SignJWT({ nonce }).setProtectedHeader({ alg: "RS256", kid: "test" }).setIssuer("https://auth.openai.com")
      .setSubject("fixture").setAudience("test-client").setExpirationTime("1h").sign(pair.privateKey);
    return Response.json({ id_token: id, access_token: "old", refresh_token: "first", expires_in: 1, scope: "chatgpt.tokens.use.direct" });
  }
  if (url === "https://api.openai.com/v1/responses") {
    assert.equal(new Headers(init.headers).get("authorization"), "Bearer fresh");
    const body = JSON.parse(init.body);
    assert.equal(body.store, false);
    assert.equal(body.stream, true);
    const events = [{ type: "response.output_text.delta", delta: "13" }, { type: "response.completed", response: { status: "completed" } }];
    messages++;
    return new Response(events.map(e => "data: " + JSON.stringify(e) + "\n\n").join(""), { headers: { "content-type": "text/event-stream" } });
  }
  if (url === "https://auth.openai.com/api/accounts/oauth/revoke") return new Response();
  throw new Error("Unexpected network request " + url);
};
const plan = await import("../lib/server/chatgpt-plan.ts");
async function attempt(validNonce) {
  const auth = new URL(await plan.startPlan("http://127.0.0.1:43210"));
  const p = auth.searchParams;
  assert.equal(p.get("code_challenge_method"), "S256");
  nonce = validNonce ? p.get("nonce") : "different";
  const cb = new URL(p.get("redirect_uri"));
  cb.search = new URLSearchParams({ state: p.get("state"), code: "fixture", client_id: "test-client" });
  return fetch(cb, { redirect: "manual" });
}
assert.equal((await attempt(false)).status, 400);
assert.equal((await plan.planStatus()).active, undefined);
assert.equal((await attempt(true)).status, 303);
const input = [{ role: "user", content: "8+5" }];
assert.deepEqual(await Promise.all([plan.planAnswer(input,"Boppy"), plan.planAnswer(input,"Boppy")]), ["13","13"]);
assert.equal(messages, 2);
assert.equal(refreshes, 1);
assert.equal(await plan.disconnectPlan(), true);
await assert.rejects(plan.planAnswer(input,"Boppy"), /Connect ChatGPT/);
console.log("ChatGPT plan: callback, signed identity, refresh, inference and disconnect passed");
