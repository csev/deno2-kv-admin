import { Hono, type Context } from "https://deno.land/x/hono@v3.4.1/mod.ts";
import { HTTPException } from "https://deno.land/x/hono@v3.12.10/http-exception.ts";
import { verifyToken } from "./dn_token.ts";

/** Enable verbose logs: set `KV_ADMIN_DEBUG` to `1`, `true`, or `yes` (case-insensitive). */
const KV_ADMIN_DEBUG = /^1|true|yes$/i.test(
  Deno.env.get("KV_ADMIN_DEBUG")?.trim() ?? "",
);

function debug(...args: unknown[]) {
  if (KV_ADMIN_DEBUG) console.debug(...args);
}

const TOKEN_SECRET = Deno.env.get("KV_TOKEN_SECRET") ?? "42";
debug(
  "[kv-admin] token HMAC secret:",
  Deno.env.has("KV_TOKEN_SECRET") ? "KV_TOKEN_SECRET from env" : "default '42'",
);

const app = new Hono();
const kv = await Deno.openKv();
debug("[kv-admin] Deno KV opened");

// Basic KV operations to support admin interface
// Multi-tenant: query ?token=... is the first KV key segment; the path after /kv/.../ is the rest.
// Example: /kv/set/pg4e/47?token=2606_dca272:04b82a -> key ["2606_dca272:04b82a", "pg4e", "47"]

// Set a record by key (POST body is JSON)
// https://pg4e-deno-kv-api-10.deno.dev/kv/set/pg4e/47?token=your_token
app.post("/kv/set/:key{.*}", async (c) => {
  const pathKey = c.req.param("key");
  const kvKey = tenantKvKey(c, pathKey);
  const body = await c.req.json();
  const result = await kv.set(kvKey, body);
  return c.json(result);
});

// Get a record by key
// https://pg4e-deno-kv-api-10.deno.dev/kv/get/pg4e/47?token=your_token
app.get("/kv/get/:key{.*}", async (c) => {
  const pathKey = c.req.param("key");
  const result = await kv.get(tenantKvKey(c, pathKey));
  return c.json(publicEntry(result));
});

// List records with a key prefix
// https://pg4e-deno-kv-api-10.deno.dev/kv/list/pg4e?token=your_token
app.get("/kv/list/:key{.*}", async (c) => {
  const pathKey = c.req.param("key");
  const cursor = c.req.query("cursor");
  const extra: Deno.KvListOptions = { limit: 100 };
  if (typeof cursor === "string" && cursor.length > 0) {
    extra.cursor = cursor;
  }
  const iter = await kv.list({ prefix: tenantKvKey(c, pathKey) }, extra);
  const records = [];
  for await (const entry of iter) {
    records.push(publicEntry(entry));
  }
  return c.json({ records, cursor: iter.cursor });
});

// Delete a record
// https://pg4e-deno-kv-api-10.deno.dev/kv/delete/pg4e/47?token=your_token
app.delete("/kv/delete/:key{.*}", async (c) => {
  const pathKey = c.req.param("key");
  const result = await kv.delete(tenantKvKey(c, pathKey));
  return c.json(result);
});

// Delete a prefix
// https://pg4e-deno-kv-api-10.deno.dev/kv/delete_prefix/pg4e?token=your_token
app.delete("/kv/delete_prefix/:key{.*}", async (c) => {
  const pathKey = c.req.param("key");
  const iter = await kv.list({ prefix: tenantKvKey(c, pathKey) });
  const keys = [];
  for await (const entry of iter) {
    kv.delete(entry.key);
    keys.push(publicKey(entry.key));
  }
  console.log("Keys with prefix", pathKey, "deleted:", keys.length);
  return c.json({ keys });
});

// Full reset for this tenant only (all keys under this token)
// https://pg4e-deno-kv-api-10.deno.dev/kv/full_reset_42?token=your_token
app.delete("/kv/full_reset_42", async (c) => {
  const token = checkToken(c);
  const iter = await kv.list({ prefix: [token] });
  const keys = [];
  for await (const entry of iter) {
    kv.delete(entry.key);
    keys.push(publicEntry(entry));
  }
  console.log("Tenant reset keys deleted:", keys.length);
  return c.json({ keys });
});

// Database-wide stats (requires valid ?token=)
// https://pg4e-deno-kv-api-10.deno.dev/stats?token=your_token
app.get("/stats", async (c) => {
  checkToken(c);
  const tokens = new Set<string>();
  const tenants = new Set<string>();
  let total_keys = 0;

  for await (const entry of kv.list({ prefix: [] })) {
    total_keys++;
    const first = entry.key[0];
    if (typeof first !== "string") continue;
    tokens.add(first);
    const colon = first.indexOf(":");
    if (colon > 0) tenants.add(first.slice(0, colon));
  }

  return c.json({
    total_keys,
    distinct_tokens: tokens.size,
    distinct_tenants: tenants.size,
  });
});

// Dump the request object for learning and debugging
// https://pg4e-deno-kv-api-10.deno.dev/dump/stuff/goes_here?key=123
app.all('/dump/*', async (c) => {
  const req = c.req

  // Request details
  const method = req.method
  const url = req.url
  const path = req.path
  const query = req.query()
  const headers: Record<string, string> = {}
  for (const [key, value] of req.raw.headers.entries()) {
    headers[key] = value
  }

  // Try to parse body as JSON, otherwise fallback to text
  let body: any = null
  try {
    body = await req.json()
  } catch {
    try {
      body = await req.text()
    } catch {
      body = null
    }
  }

  const dump = {
    method,
    url,
    path,
    headers,
    query,
    body,
  }

  return c.json(dump, 200)
});

// Make sure we return the correct HTTP Status code when we throw an exception
app.onError((err, c) => {
  if (err instanceof HTTPException) {
    return c.text(err.message, err.status);
  }
  return c.text('Internal Server Error', 500);
});

/**
 * Query `?token=...` must be signed: `signedPayload` + `:` + 6 hex chars = md5(signedPayload:secret)[0..6].
 * Secret is `KV_TOKEN_SECRET` or default `'42'`. Path is not used for auth.
 */
function checkToken(c: Context): string {
  const token = c.req.query("token");
  if (typeof token !== "string" || token.length === 0) {
    debug("[checkToken] rejected: missing or empty token query");
    throw new HTTPException(401, { message: "Missing or invalid token" });
  }

  const v = verifyToken(token, TOKEN_SECRET);
  if (v.debug) debug("[checkToken]", v.debug);
  if (!v.ok) {
    debug("[checkToken] rejected:", v.reason);
    throw new HTTPException(401, { message: "Missing or invalid token" });
  }

  return token;
}

/** Full KV key: [token, ...path segments from the URL]. */
function tenantKvKey(c: Context, pathKey: string): Deno.KvKey {
  const token = checkToken(c);
  const segments = pathKey.split("/").filter((s) => s.length > 0);
  return [token, ...segments];
}

/** JSON responses omit the tenant token (first key segment). */
function publicKey(kvKey: Deno.KvKey): Deno.KvKey {
  return kvKey.length > 1 ? kvKey.slice(1) : [];
}

function publicEntry<T>(entry: Deno.KvEntry<T>): {
  key: Deno.KvKey;
  value: T;
  versionstamp: string;
} {
  return {
    key: publicKey(entry.key),
    value: entry.value,
    versionstamp: entry.versionstamp,
  };
}


// If you are putting up your own server you can either delete this
// CRON entry or change it to be once per month with "0 0 1 * *" as
// the CRON string
Deno.cron("Hourly DB Reset", "0 * * * *", async () => {
  const ckv = await Deno.openKv();
  const iter = await ckv.list({ prefix: [] });
  const keys = [];
  let count = 0;
  for await (const entry of iter) {
    ckv.delete(entry.key);
    count++;
    if ( count < 10 ) keys.push(entry.key);
  }
  console.log("Hourly reset keys deleted:", count, keys);
});

Deno.serve(app.fetch);
