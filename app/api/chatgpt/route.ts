import { disconnectPlan, planMode, planStatus, startPlan } from "@/lib/server/chatgpt-plan";

export const dynamic = "force-dynamic";
const escape = (v: string) => v.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
function local(request: Request) {
  const host = request.headers.get("host") ?? "";
  return planMode() && /^127\.0\.0\.1(?::\d+)?$/.test(host) ? "http://" + host : null;
}
export async function GET(request: Request) {
  if (!local(request)) return new Response("Local pilot only", { status: 403 });
  const { accounts, active } = await planStatus();
  const chosen = accounts.find(a => a.clientId === active);
  const forms = accounts.map(a => '<form method="post"><input type="hidden" name="client" value="' + escape(a.clientId) + '"><button>Reconnect ' + escape(a.email ?? "account") + ' (' + escape(a.clientId.slice(-6)) + ')</button></form>').join("");
  return new Response('<!doctype html><meta charset=utf-8><title>ChatGPT for Bops</title><main style="font:16px system-ui;max-width:38rem;margin:10vh auto"><h1>ChatGPT for Bops</h1><p>Use your ChatGPT plan for direct bot chat and web research.</p><p>' + (chosen ? 'Connected as ' + escape(chosen.email ?? "your ChatGPT account") : 'No ChatGPT account connected.') + '</p>' + forms + '<form method="post"><button>Continue with ChatGPT</button></form>' + (chosen ? '<form method="post"><button name="action" value="disconnect">Disconnect active account</button></form>' : '') + '<p><a href="/">Return to Bops</a> · <a href="https://chatgpt.com/settings/usage">Manage ChatGPT usage</a></p></main>',
    { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'", "Referrer-Policy": "no-referrer" } });
}
export async function POST(request: Request) {
  const origin = local(request);
  if (!origin || request.headers.get("origin") !== origin) return new Response("Local Bops window only", { status: 403 });
  const data = await request.formData();
  if (data.get("action") === "disconnect") {
    const revoked = await disconnectPlan();
    if (!revoked) return new Response("Disconnected locally. Remote revocation was not confirmed. Review access in ChatGPT Settings.");
    return Response.redirect(origin + "/api/chatgpt", 303);
  }
  const client = data.get("client");
  return Response.redirect(await startPlan(origin, typeof client === "string" ? client : undefined), 303);
}
