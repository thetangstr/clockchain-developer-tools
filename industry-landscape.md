# Industry Landscape - Timestamping, Notarization & Provenance

What the leading platforms in Clockchain's space actually do, with evidence.
Researched 2026-06-02 via web + social signal. The goal is to ground our
product decisions in what established players ship, not assumptions.

Three tiers are relevant to Clockchain:

1. **Direct comparables** - blockchain timestamping / proof-of-existence APIs
2. **Supply-chain provenance** - Sigstore and RFC 3161 timestamp authorities
3. **Content provenance** - C2PA / Content Credentials and the regulation driving it

---

## 1. Direct comparables: blockchain timestamping APIs

These do exactly what Clockchain's logging feature does - hash an asset, anchor
the fingerprint on a chain, return a verifiable proof. They are the most direct
benchmark for developer experience.

| Platform | Anchoring | Developer surface | Notable |
|---|---|---|---|
| [OpenTimestamps](https://opentimestamps.org/) | Bitcoin | Open protocol, CLI, libraries; hash computed locally | Free, vendor-independent, the de-facto open standard |
| [OriginStamp](https://docs.originstamp.com/api/) | Bitcoin + Ethereum | Single REST call; SDKs for Python, Java, Node.js | "Integrate in hours, not weeks"; returns a verifiable certificate |
| [Stampery](https://docs.stampery.com/) | Bitcoin + Ethereum | REST API; clients for Node, PHP, Python, Ruby, Elixir, Java, Go | "Industrial-scale data certification"; proves existence, integrity, ownership |
| [ProofLedger](https://proofledger.io/) | Polygon + Bitcoin | API; SHA-256 anchoring | Dual-chain: Polygon for speed, Bitcoin for daily batched merkle proofs |
| [BlockNotary](https://www.blocknotary.com/timestamp) | Bitcoin / Ethereum via OTS + IPFS | Hosted + API | "100% distributed proofs" using OpenTimestamps and IPFS |

**What they consistently get right, that Clockchain does not yet:**

- **One REST call, no wallet.** OriginStamp's pitch is a *single* HTTP call returns
  a certificate ([OriginStamp docs](https://docs.originstamp.com/guide/gettingstarted.html)).
  No MetaMask, no gas, no token swap. Clockchain's logging works, but funding it
  currently routes through a Sepolia token swap (see `product-findings.md` #2-3).
- **Local hashing for privacy.** OpenTimestamps "calculates hash values locally
  inside the browser without disclosing the document" ([dgi.io/ots](https://dgi.io/ots/)).
  The data never leaves the client; only the hash is submitted. Clockchain does
  this too - worth making explicit in marketing.
- **Multi-language SDKs out of the box.** Stampery ships seven client libraries
  ([stampery/node](https://github.com/stampery/node)); OriginStamp ships Python,
  Java, Node ([originstamp-client-python](https://github.com/OriginStampTimestamping/originstamp-client-python)).
  Clockchain has none yet - this is exactly the gap our `@clockchain/core` + CLI
  + MCP plan fills.
- **Multi-chain anchoring as a trust story.** Every serious player anchors to
  more than one chain (Bitcoin for permanence, a faster chain for confirmation).
  Clockchain's single-node testnet is a weaker trust position by comparison.

**Cost reality of the Bitcoin approach.** OpenTimestamps creator Peter Todd,
on X: "Bitcoin is an extremely expensive data storage layer ... If you're willing
to pay a lot of money per byte to ensure your data never gets lost, there is
nothing remotely comparable to Bitcoin right now"
([@peterktodd](https://x.com/peterktodd/status/2057452057913954509)). This is the
opening Clockchain's subnet architecture targets - cheaper high-volume anchoring
than putting everything on Bitcoin. It is a real, defensible wedge if the cost
and throughput numbers hold.

---

## 2. Supply-chain provenance: Sigstore + RFC 3161

This is the enterprise-credible tier. If Clockchain wants the "legal-grade,
audit-trail" positioning, this is the bar.

- **[Sigstore's timestamp-authority](https://github.com/sigstore/timestamp-authority)**
  is a production RFC 3161 Timestamp Authority and a core component of the Sigstore
  stack. Kong and Chainguard ship hardened builds
  ([Kong fork](https://github.com/Kong/sigstore-timestamp-authority),
  [Chainguard image](https://images.chainguard.dev/directory/image/timestamp-authority-server/overview)).
- **The model: signed timestamps, no chain required.** Per
  [Sigstore's "Trusted Time" post](https://blog.sigstore.dev/trusted-time/),
  TSAs issue signed timestamps following RFC 3161; "since the timestamps are
  signed, the time becomes immutable and verifiable." Anyone can operate a TSA.
  This is a lighter-weight competitor to blockchain anchoring - and it is what
  regulated industries already accept.
- **Regulation is the demand driver.** Sigstore's own analysis notes that
  "organizations in regulated sectors cannot adopt model-signing due to lack of
  timestamp support, as eIDAS (EU) requires qualified timestamps from approved
  Timestamp Authorities, FDA (US) requires trusted timestamps for electronic
  records, and financial services and healthcare regulations mandate timestamped
  audit trails" ([Sigstore docs](https://docs.sigstore.dev/cosign/verifying/timestamps/)).

**Takeaway for Clockchain.** The legal standards Clockchain's audit doc cites
(eIDAS, RFC 3161) are exactly what Sigstore already serves with signed
timestamps - without a blockchain. To win the "court-grade" argument, Clockchain
has to show its decentralized multi-validator consensus is *better* than a signed
TSA timestamp, not merely equivalent. On a single-node testnet it currently is
not (see `product-findings.md` #7). This is a positioning risk worth taking
seriously.

---

## 3. Content provenance: C2PA and the regulatory clock

This is the fastest-moving adjacent tier and the one closest to the "AI agent
provenance" story Product B is chasing.

- **[C2PA / Content Credentials](https://c2paviewer.com/articles/what-is-c2pa)**
  is an open standard (Adobe, Arm, BBC, Intel, Microsoft, founded 2021) that
  embeds tamper-evident provenance into media: who made it, when, with what tools.
- **Verification needs no callback.** "The verification step requires no network
  call to the original signer. All required certificates travel inside the
  manifest" ([C2PA viewer](https://c2paviewer.com/articles/what-is-c2pa)). That
  offline-verifiable property is something Clockchain's proof flow should aim for -
  today our `prove verify` still needs an API call to re-read the chain.
- **Regulation has a date.** "EU AI Act Article 50 enforcement begins August 2026,
  requiring machine-readable disclosure on AI-generated content"
  ([eyesift](https://www.eyesift.com/faq/c2pa-content-credentials-2026-cryptographic-provenance-adoption/)).
  OpenAI, Google, and Adobe are moving it into production
  ([SoftwareSeni](https://www.softwareseni.com/c2pa-adoption-in-2026-hardware-platforms-and-verification-reality/)).
- **The "audit log of agent actions" pattern already exists.** One vendor
  "maintains an internal audit log of every signed manifest: timestamp, customer
  ID, content hash, signing certificate fingerprint"
  ([DeepSwapAI](https://deepswapai.com/c2pa-content-credentials-deepswapai-provenance-2026)).
  That is almost exactly Clockchain's `log_action` schema - which validates the
  Product B direction, but also means the pattern is not unique to us.

**The cultural signal.** On X, the framing that is gaining traction: "In the AI
era, VERIFIED RECEIPTS become more valuable than attention ... Bitcoin-anchored
via OpenTimestamps. Mathematically unerasable"
([@geoff_deweaver](https://x.com/geoff_deweaver/status/2059562302115082658)).
The market for "prove this is real / prove an AI did this" is forming now. That
is Clockchain's tailwind - but OpenTimestamps is already the name attached to it.

---

## 4. How the industry handles paying for usage (the token question)

This is the specific question: is buying logging credits with a crypto token,
through a wallet, paying a network fee, the industry standard? The evidence says
clearly **no** - and where crypto is used well, it looks nothing like
Clockchain's current flow.

**The default is prepaid fiat credits via Stripe.** OpenAI's API uses a prepaid
credit system - buy credits in advance ($5 minimum), usage deducts from the
balance, with auto-recharge ([TokenMix](https://tokenmix.ai/blog/openai-api-billing-explained)).
This is the dominant pattern. A 2026 survey of the field concludes "prepaid fiat
credits via Stripe-like payment methods appear to be the industry standard, while
crypto token-based billing remains less common as a primary payment mechanism"
([Cryptopolitan](https://www.cryptopolitan.com/the-12-best-crypto-api-providers-for-developers-in-2026/)).
Even crypto-forward platforms split the difference: Nevermined uses "Stripe
integration for fiat ... and Coinbase for stablecoin settlement," outsourcing the
payment rails entirely ([Nevermined](https://nevermined.ai/blog/ai-agent-payment-systems)).

**Where crypto IS the rail, the standard is x402 - and it is gasless USDC, not a
project token.** Coinbase's [x402](https://docs.cdp.coinbase.com/x402/welcome)
revives HTTP 402 to let clients (humans or AI agents) pay for an API call inline,
"without accounts, sessions, or complex authentication." The mechanics are the
exact opposite of Clockchain's flow:

- **Gasless.** "The payment is a gasless USDC transfer on Base ... The user signs
  the transfer locally but doesn't submit it to the blockchain. Instead, they send
  the signature to the server, and the facilitator handles the on-chain settlement"
  ([Sherlock](https://sherlock.xyz/post/x402-explained-the-http-402-payment-protocol)).
  The user never holds or spends a gas token.
- **Stablecoin, not a volatile native token.** Settlement is in USDC via EIP-3009,
  "for the smoothest experience" ([Coinbase](https://www.coinbase.com/developer-platform/discover/launches/x402)).
- **Built for agents.** "Let AI agents pay and access services autonomously with
  no keys or human input needed."
- **Real scale and serious backers.** 119M+ transactions on Base, ~$600M
  annualized volume, zero protocol fees; the x402 Foundation includes Coinbase,
  Cloudflare, Google, Visa, AWS, Circle, **Anthropic**, and Vercel
  ([Coinbase](https://www.coinbase.com/developer-platform/discover/launches/x402)).

This matters directly: x402 is the standard being built for exactly Clockchain's
Product B use case - an AI agent paying per API call. And it is gasless USDC.

**Why Clockchain's flow is so complicated.** It uses the pre-2023 model that the
rest of the industry has already engineered around:

1. **You pay in a volatile project token (`d4dt`), not a stablecoin.** Pricing in
   your own token means the buyer takes on token-price risk just to buy logs.
2. **You pay gas in a separate native token you don't hold.** Every ERC-20 transfer
   requires the sender to own the chain's gas token. This is the classic trap:
   "I want to send my USDC, but I first need to buy ETH to pay the fees?"
   ([Fibo](https://fibo-crypto.fr/en/blog/account-abstraction-gasless-guide-en/)).
   On Clockchain you hold `d4dt` but no SepoliaETH, so you can't move the `d4dt`.
3. **It runs on a testnet (Sepolia)**, so the "payment" isn't even real value
   movement - it's testnet plumbing exposed to the user.
4. **No gas abstraction.** Since 2023, ERC-4337 account abstraction and
   **paymasters** solve exactly this. "An ERC-20 paymaster allows users to pay gas
   fees using a supported ERC-20 token ... users only ever think in dollars, and
   never need to acquire ETH"
   ([thirdweb](https://blog.thirdweb.com/account-abstraction-gas-fees-paymasters-bundlers-cost-optimization/)).
   Clockchain implements none of this, so the raw gas requirement leaks straight
   to the user.

In short: the wallet-plus-gas purchase is not an industry standard - it is the
specific thing the industry spent the last three years removing. The fix is one
of two well-trodden paths: (a) **fiat prepaid credits via Stripe** as the default,
or (b) if crypto is wanted, **gasless stablecoin** (x402 / USDC with a paymaster),
never a volatile token the user has to fund with gas.

---

## What the leaders do that we should copy

1. **Single REST call, no wallet, fiat-simple.** Every successful timestamping
   API hides the chain entirely. The developer sends a hash and gets a proof.
   Clockchain's logging is technically there; the funding flow is not.
2. **Multi-language SDKs from day one.** Stampery (7 languages) and OriginStamp
   (3+) treat SDKs as table stakes. Our CLI + MCP + core plan is the right shape;
   ship it.
3. **Offline verification.** C2PA verifies with no callback. Clockchain proofs
   should be self-contained where possible.
4. **Multi-anchor trust.** Dual-chain anchoring (fast + permanent) is the norm.
   A single node is a visible weakness.
5. **Lead with the regulation.** eIDAS, RFC 3161, FDA, EU AI Act Article 50
   (Aug 2026) are driving real budget. The platforms that name the regulation
   they satisfy win the regulated buyer. Clockchain can only make this claim
   honestly once it has a real validator set.

## Where Clockchain can actually differentiate

- **Cost at volume.** Bitcoin anchoring is expensive (per Peter Todd). Clockchain's
  subnet architecture - logs in a dedicated subnet, one state-root hash to mainnet
  per cycle - is a genuine answer to high-volume enterprise logging that pure
  Bitcoin anchoring cannot match on price. This is the strongest wedge.
- **Agent-native funding and identity.** None of the timestamping incumbents have
  an answer for "an AI agent that logs its own actions and pays per write via an
  API credit, not a wallet." That is an open lane - *if* Clockchain fixes the
  funding model (see `product-findings.md` #3).
- **Time as the primitive, not an afterthought.** The incumbents timestamp as a
  side effect of notarization. Clockchain's Marzullo multi-source consensus makes
  *the time itself* the product. That is a real technical differentiator, but only
  legible once consensus runs on more than one node.

---

## Evidence base

Social signal for this topic is thin - developers discuss timestamping in docs
and GitHub, not on Reddit/TikTok - so this draws mainly from platform
documentation and the web. The `/last30days` engine pass surfaced 25 items
(20 X, 3 Hacker News, 2 GitHub); the substantive evidence is the platform docs
and standards bodies cited inline above. Raw research saved to
`~/Documents/Last30Days/blockchain-timestamping-notarization-proof-of-existence-developer-platforms-raw-v3.md`.
