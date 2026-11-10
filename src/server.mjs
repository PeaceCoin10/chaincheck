/**
 * chaincheck — on-chain due diligence for agents, paid per call over x402.
 *
 * One paid route:  GET /v1/check/:address   ($0.01, USDC on Base)
 * Free routes:     /  /.well-known/x402  /openapi.json  /health
 *
 * Everything the paid route returns is derived from two keyless sources:
 *   1. Base JSON-RPC  eth_getCode   (bytecode, size)
 *   2. Sourcify v2    contract/{chainId}/{address}   (verification, name, compiler)
 * No API keys, no database, no gas. The seller only needs a receiving address.
 */
import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { declareDiscoveryExtension, bazaarResourceServerExtension } from "@x402/extensions/bazaar";

const PORT = Number(process.env.PORT ?? 4021);
const PAY_TO = process.env.PAY_TO ?? "0x436b9d5e6fBd40eC93E881263bE53e59F8755Ba1";
const FACILITATOR = process.env.FACILITATOR_URL ?? "https://facilitator.xpay.sh";
const RPC = process.env.BASE_RPC ?? "https://mainnet.base.org";
const SOURCIFY = process.env.SOURCIFY_URL ?? "https://sourcify.dev/server";
const PRICE = process.env.PRICE ?? "$0.01";
const NETWORK = "eip155:8453"; // Base mainnet
const CHAIN_ID = 8453;
const SERVICE = "chaincheck";
const VERSION = "0.1.0";

/* ---------------------------------- opcodes -------------------------------- */

const OP = { DELEGATECALL: 0xf4, SELFDESTRUCT: 0xff, STATICCALL: 0xfa, CALLCODE: 0xf2, EQ: 0x14, PUSH4: 0x63 };

/**
 * Minimal EVM disassembler. PUSH data must be skipped byte-exactly, otherwise a
 * `0xff` inside a constant is misread as SELFDESTRUCT and the risk score lies.
 */
function disassemble(codeHex) {
  const hex = codeHex.startsWith("0x") ? codeHex.slice(2) : codeHex;
  const ops = [];
  let i = 0;
  while (i < hex.length - 1) {
    const op = parseInt(hex.slice(i, i + 2), 16);
    if (op >= 0x60 && op <= 0x7f) {
      const n = op - 0x5f;
      ops.push({ op, data: hex.slice(i + 2, i + 2 + n * 2) });
      i += 2 + n * 2;
    } else {
      ops.push({ op, data: null });
      i += 2;
    }
  }
  return ops;
}

/** Function selectors = PUSH4 immediates that are immediately compared with EQ. */
function push4Selectors(ops) {
  const out = new Set();
  for (let k = 0; k < ops.length; k++) {
    if (ops[k].op === OP.PUSH4 && ops[k + 1]?.op === OP.EQ) out.add("0x" + ops[k].data);
  }
  return out;
}

const SEL = {
  mint: ["0x40c10f19"], // mint(address,uint256)
  upgradeTo: ["0x3659cfe6", "0x4f1ef286"], // upgradeTo(address), upgradeToAndCall(address,bytes)
  transferOwnership: ["0xf2fde38b"],
  renounceOwnership: ["0x715018a6"],
  pause: ["0x8456cb59"],
  selfdestructNamed: ["0x9cb8a26a"], // selfdestruct() exposed as a function
};

/* --------------------------------- fetching -------------------------------- */

const TIMEOUT = 12_000;
const fetchJson = async (url, init = {}) => {
  const r = await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT) });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} from ${new URL(url).host}`);
  return r.json();
};

async function getCode(address) {
  const body = { jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, "latest"] };
  const j = await fetchJson(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (j.error) throw new Error(`rpc: ${j.error.message}`);
  return j.result;
}

async function getVerification(address) {
  try {
    const j = await fetchJson(`${SOURCIFY}/v2/contract/${CHAIN_ID}/${address}?fields=compilation`);
    const c = j.compilation ?? {};
    return {
      verified: Boolean(j.match && j.match !== "not_found"),
      match: j.match ?? null,
      name: c.name ?? null,
      fullyQualifiedName: c.fullyQualifiedName ?? null,
      compiler: c.compilerVersion ?? null,
      language: c.language ?? null,
      optimizer: c.compilerSettings?.optimizer ?? null,
      verifiedAt: j.verifiedAt ?? null,
    };
  } catch (e) {
    return { verified: false, match: null, error: String(e.message ?? e) };
  }
}

/* ---------------------------------- scoring -------------------------------- */

function score({ isContract, codeSize, verification, ops, selectors }) {
  if (!isContract) {
    return { score: 0, grade: "EOA", flags: [{ flag: "not_a_contract", weight: 0, note: "no bytecode at this address" }] };
  }
  const flags = [];
  const add = (flag, weight, note) => flags.push({ flag, weight, note });

  if (!verification.verified) add("source_unverified", 45, "no exact_match source on Sourcify: cannot audit read the logic");
  else if (verification.match !== "exact_match") add("source_partial_match", 12, `source match is ${verification.match}`);

  const hasSelfdestruct = ops.some((o) => o.op === OP.SELFDESTRUCT);
  const hasDelegatecall = ops.some((o) => o.op === OP.DELEGATECALL);
  const hasCallcode = ops.some((o) => o.op === OP.CALLCODE);

  if (hasSelfdestruct) add("selfdestruct", 25, "SELFDESTRUCT opcode reachable in bytecode");
  if (hasCallcode) add("callcode", 20, "CALLCODE opcode present (legacy, unsafe semantics)");
  if (hasDelegatecall) add("delegatecall", 10, "DELEGATECALL present: proxy or library call, check the target");
  if (codeSize < 300) add("tiny_bytecode", 15, `only ${codeSize} bytes: stub or minimal proxy`);
  if (codeSize > 24500) add("near_size_limit", 8, `${codeSize} bytes, close to the 24 KB limit`);

  for (const [name, sigs] of Object.entries(SEL)) {
    if (sigs.some((s) => selectors.has(s))) add(`has_${name}`, name === "mint" ? 8 : name === "upgradeTo" ? 12 : 3, `exposes ${name}()`);
  }
  if (hasDelegatecall && codeSize < 300) add("proxy_pattern", 8, "small code + DELEGATECALL: almost certainly an upgradeable proxy");

  const clean = flags.filter((f) => f.weight > 0);
  const total = Math.min(100, clean.reduce((a, f) => a + f.weight, 0));
  const grade = total < 15 ? "A" : total < 30 ? "B" : total < 50 ? "C" : total < 70 ? "D" : "F";
  return { score: total, grade, flags: clean };
}

/* ---------------------------------- report --------------------------------- */

async function buildReport(rawAddress) {
  const address = rawAddress.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(address)) {
    const err = new Error("address must be a 40-hex-character 0x-prefixed string");
    err.status = 400;
    throw err;
  }
  const code = await getCode(address);
  const isContract = Boolean(code && code !== "0x");
  const codeSize = isContract ? (code.length - 2) / 2 : 0;
  const ops = isContract ? disassemble(code) : [];
  const selectors = isContract ? push4Selectors(ops) : new Set();

  const verification = isContract ? await getVerification(address) : { verified: false, match: null };
  const risk = score({ isContract, codeSize, verification, ops, selectors });

  return {
    address,
    chain: "base",
    chainId: CHAIN_ID,
    checkedAt: new Date().toISOString(),
    contract: {
      isContract,
      codeSize,
      proxySuspect: isContract && ops.some((o) => o.op === OP.DELEGATECALL) && codeSize < 300,
      opcodes: isContract
        ? {
            delegatecall: ops.some((o) => o.op === OP.DELEGATECALL),
            selfdestruct: ops.some((o) => o.op === OP.SELFDESTRUCT),
            callcode: ops.some((o) => o.op === OP.CALLCODE),
            staticcall: ops.some((o) => o.op === OP.STATICCALL),
          }
        : null,
      functionSelectors: selectors.size,
      selectors: [...selectors].slice(0, 40),
    },
    verification,
    risk,
    disclosure: {
      sources: ["eth_getCode via public Base RPC", "Sourcify v2 exact-match registry"],
      notCovered: [
        "logic bugs, economic exploits, access-control mistakes",
        "storage state, balances, holders, upgrade history",
        "any off-chain behaviour or governance",
      ],
      note: "Automated static screening, not an audit. Treat grade as a filter, not a verdict.",
    },
  };
}

/* ---------------------------------- server --------------------------------- */

const routes = {
  "GET /v1/check/:address": {
    accepts: { scheme: "exact", payTo: PAY_TO, price: PRICE, network: NETWORK },
    description:
      "On-chain due-diligence report for a Base address: bytecode screening, verification status, risk grade.",
    mimeType: "application/json",
    serviceName: SERVICE,
    tags: ["due-diligence", "security", "base", "smart-contracts", "risk"],
    unpaidResponseBody: () => ({
      contentType: "application/json",
      body: {
        error: "payment_required",
        price: PRICE,
        network: NETWORK,
        asset: "USDC",
        payTo: PAY_TO,
        hint: "Retry the same URL with a PAYMENT-SIGNATURE header from any x402 v2 client.",
        freePreview: "GET / -> catalog, GET /health -> status",
      },
    }),
    extensions: declareDiscoveryExtension({
      method: "GET",
      input: { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" },
      inputSchema: {
        properties: {
          address: {
            type: "string",
            pattern: "^0x[0-9a-fA-F]{40}$",
            description: "Base address to screen (contract or EOA)",
          },
        },
        required: ["address"],
      },
      output: {
        example: {
          address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
          chain: "base",
          chainId: 8453,
          contract: {
            isContract: true,
            codeSize: 1852,
            proxySuspect: false,
            opcodes: { delegatecall: true, selfdestruct: false, callcode: false, staticcall: false },
            functionSelectors: 5,
          },
          verification: { verified: true, match: "exact_match", name: "FiatTokenProxy", compiler: "0.6.12+commit.27d51765" },
          risk: { score: 22, grade: "B", flags: [{ flag: "delegatecall", weight: 10 }] },
        },
      },
    }),
  },
};

const facilitator = new HTTPFacilitatorClient({ url: FACILITATOR });
const resourceServer = new x402ResourceServer(facilitator)
  .register(NETWORK, new ExactEvmScheme())
  .registerExtension(bazaarResourceServerExtension);

const app = express();
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("access-control-allow-origin", "*");
  res.setHeader("access-control-allow-headers", "content-type,payment-signature,payment-required");
  res.setHeader("access-control-expose-headers", "payment-response,payment-required");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const catalog = () => ({
  service: SERVICE,
  version: VERSION,
  description:
    "On-chain due diligence for autonomous agents. Pay per call in USDC on Base; no account, no API key.",
  network: NETWORK,
  payTo: PAY_TO,
  currency: "USDC",
  resources: [
    {
      path: "/v1/check/:address",
      method: "GET",
      price: PRICE,
      mimeType: "application/json",
      description:
        "Bytecode screening + Sourcify verification + 0-100 risk grade for any Base address. Checks SELFDESTRUCT/DELEGATECALL/CALLCODE by real disassembly (PUSH data skipped), selector inventory, size and proxy patterns.",
      example: { request: "GET /v1/check/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" },
    },
  ],
  free: ["/", "/.well-known/x402", "/openapi.json", "/health"],
});

app.get("/", (_req, res) => res.json(catalog()));

/**
 * x402scan / directory discovery (spec: Merit-Systems/x402scan docs/DISCOVERY.md).
 * Shape must be {version, resources:[absolute urls]} — a catalog-shaped body is ignored.
 */
/** Public base URL. cloudflared quick tunnels often omit x-forwarded-proto, so
 *  anything that is not a local/LAN host is assumed to be served over TLS. */
const publicBase = (req) => {
  const host = req.get("host") ?? "";
  const local = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|192\.168\.|10\.)/.test(host);
  const proto = req.get("x-forwarded-proto") || (local ? req.protocol : "https");
  return `${proto}://${host}`;
};

app.get("/.well-known/x402", (req, res) => {
  const base = publicBase(req);
  res.json({
    version: 1,
    resources: [`${base}/v1/check/:address`],
    ownershipProofs: [PAY_TO],
    instructions: `Paid route: GET ${base}/v1/check/<base-address> for ${PRICE} USDC on Base (${NETWORK}). Any x402 v2 client works; no account or API key.`,
  });
});

app.get("/health", (_req, res) =>
  res.json({ status: "ok", service: SERVICE, version: VERSION, network: NETWORK, price: PRICE, uptime: process.uptime() }),
);

app.get("/openapi.json", (req, res) => {
  const base = publicBase(req);
  res.json({
    openapi: "3.0.3",
    info: { title: SERVICE, version: VERSION, description: catalog().description },
    "x-discovery": { ownershipProofs: [PAY_TO] },
    servers: [{ url: base }],
    paths: {
      "/v1/check/{address}": {
        get: {
          summary: "On-chain due-diligence report for a Base address",
          operationId: "checkAddress",
          tags: ["due-diligence", "security", "base"],
          parameters: [
            {
              name: "address",
              in: "path",
              required: true,
              schema: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
              description: "Base address to screen (contract or EOA)",
            },
          ],
          "x-payment-info": {
            protocols: ["x402"],
            price: { mode: "fixed", currency: "USD", amount: "0.01" },
            network: NETWORK,
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            payTo: PAY_TO,
          },
          responses: {
            200: { description: "Screening report", content: { "application/json": { schema: { type: "object" } } } },
            402: {
              description: `Payment required: ${PRICE} USDC on Base (${NETWORK})`,
              headers: { "PAYMENT-REQUIRED": { schema: { type: "string" } } },
            },
            400: { description: "Malformed address" },
          },
        },
      },
    },
  });
});

app.use(paymentMiddleware(routes, resourceServer));

app.get("/v1/check/:address", async (req, res) => {
  try {
    const report = await buildReport(req.params.address);
    res.json(report);
  } catch (e) {
    res.status(e.status ?? 502).json({ error: "report_failed", message: String(e.message ?? e) });
  }
});

app.use((_req, res) => res.status(404).json({ error: "not_found", see: "/" }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[${SERVICE}] listening on :${PORT}  price=${PRICE}  network=${NETWORK}  payTo=${PAY_TO}`);
  console.log(`[${SERVICE}] facilitator=${FACILITATOR}  rpc=${RPC}`);
});
