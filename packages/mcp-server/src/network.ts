// Which Clockchain network this deployment is on, in one place. SHADOW_NETWORK=mainnet is the switch; anything else is
// testnet, and the text on testnet stays as it was. What mainnet costs isn't decided, so on mainnet the pages make no
// promise about free use, and the anonymous free key is off unless MCP_MAINNET_FREE_TOKENS=1 says otherwise: it spends the
// server's own credits, and there those would be real. Signed-in accounts keep working on Shadow, within their limits.
export const ON_MAINNET = (process.env.SHADOW_NETWORK ?? "").trim() === "mainnet";
/** Anything else is a typo, and a typo would quietly leave the server on testnet's rules with mainnet's credits. */
const named = (process.env.SHADOW_NETWORK ?? "").trim();
export const NETWORK_PROBLEM = ["", "testnet", "mainnet"].includes(named) ? null : "SHADOW_NETWORK must be testnet or mainnet";
export const NETWORK_WORD = ON_MAINNET ? "mainnet" : "testnet";
export const NETWORK_LABEL = ON_MAINNET ? "Mainnet" : "Testnet";
export const FREE_TOKENS = !ON_MAINNET || (process.env.MCP_MAINNET_FREE_TOKENS ?? "").trim() === "1";
