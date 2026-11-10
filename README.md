# chaincheck

On-chain due diligence for agents. One HTTP call, one payment in USDC, a
screening report on any address on Base.

No account. No API key. No subscription. A buyer needs only a wallet with USDC.

```
GET https://<host>/v1/check/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
→ 402 Payment Required   (price, network, payTo in the PAYMENT-REQUIRED header)
→ retry with PAYMENT-SIGNATURE from any x402 v2 client
→ 200 { report }
```

## What it actually checks

Everything below is derived from two keyless sources — a public Base RPC and the
Sourcify v2 registry. Nothing is guessed and nothing is stored.

| Field | How it is obtained |
| --- | --- |
| `contract.isContract`, `codeSize` | `eth_getCode` on Base mainnet |
| `contract.opcodes.*` | real disassembly of the runtime bytecode, **PUSH data skipped** |
| `contract.selectors` | `PUSH4` immediates that are compared with `EQ` |
| `contract.proxySuspect` | small code + `DELEGATECALL` |
| `verification.*` | Sourcify v2 `exact_match`, contract name, compiler, optimizer |
| `risk.score` / `grade` | weighted flags, see below |

The disassembler matters: a naive `bytecode.includes("ff")` reports a
`SELFDESTRUCT` inside a constant and inflates the score. This one walks opcodes
and skips push immediates, so `SELFDESTRUCT`, `DELEGATECALL`, `CALLCODE` and
`STATICCALL` are only reported when they are reachable instructions.

Risk weights: `source_unverified` 45, `selfdestruct` 25, `callcode` 20,
`tiny_bytecode` 15, `source_partial_match` 12, `upgradeTo` 12, `delegatecall` 10,
`near_size_limit` 8, `proxy_pattern` 8, `mint` 8, `pause`/`renounce` 3.
Grades: A <15, B <30, C <50, D <70, F ≥70.

## What it does not do

Stated in every response under `disclosure.notCovered`:

- no logic bugs, economic exploits or access-control review
- no storage, balances, holders or upgrade history
- no off-chain behaviour

It is an automated static filter, not an audit. A grade is a starting point for a
human or an agent, not a verdict.

## Run it

```bash
npm install
PAY_TO=0xYourReceivingAddress PORT=4021 node src/server.mjs

curl -s localhost:4021/health
curl -si localhost:4021/v1/check/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 | head -3
```

Environment:

| Var | Default | Meaning |
| --- | --- | --- |
| `PAY_TO` | — | address that receives USDC |
| `PORT` | 4021 | listen port |
| `FACILITATOR_URL` | `https://facilitator.xpay.sh` | x402 facilitator, keyless, settles `eip155:8453` |
| `BASE_RPC` | `https://mainnet.base.org` | read-only RPC |
| `SOURCIFY_URL` | `https://sourcify.dev/server` | verification registry |
| `PRICE` | `$0.01` | per call |

## Self-test the payment loop

```bash
node scripts/buy.mjs http://127.0.0.1:4021/v1/check/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
```

It signs an EIP-3009 authorization with the key in `BUYER_KEY_FILE` (default
`/root/.aura/deployer.key`). Pointing `PAY_TO` at the same address makes the USDC
round-trip, so the test costs one facilitator-paid gas transaction and nothing
else.

## Why a free preview is not offered

A partial free response would make the report rankable by scrapers and remove the
reason to pay. The 402 body carries the price, network, asset and a hint instead —
enough for an agent to decide, not enough to substitute for the answer.

## License

MIT
