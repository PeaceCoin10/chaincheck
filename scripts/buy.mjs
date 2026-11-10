/**
 * Self-test buyer: pays the local chaincheck endpoint $0.01 USDC on Base.
 *
 * Buyer key is the deployer/treasury key, and payTo is the same address, so the
 * USDC makes a round trip and the only real cost is one facilitator-paid gas tx.
 * Proves: 402 -> EIP-3009 signature -> facilitator settle -> 200 + report.
 */
import { wrapFetchWithPayment } from "@x402/fetch";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "node:fs";

const key = readFileSync(process.env.BUYER_KEY_FILE ?? "/root/.aura/deployer.key", "utf8").trim();
const signer = privateKeyToAccount(key.startsWith("0x") ? key : `0x${key}`);
const url = process.argv[2] ?? "http://127.0.0.1:4021/v1/check/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

const client = new x402Client();
client.register("eip155:*", new ExactEvmScheme(signer));
const pay = wrapFetchWithPayment(fetch, client);

console.log("buyer:", signer.address);
console.log("url:  ", url);

const res = await pay(url, { method: "GET" });
console.log("status:", res.status);
const text = await res.text();
console.log("body:  ", text.slice(0, 1200));

const hdrs = {};
res.headers.forEach((v, k) => (hdrs[k.toLowerCase()] = v));
console.log("payment-response:", hdrs["payment-response"] ?? "(none)");
