import type { App } from "e2e";

export const ACT_BUTTON = {
  act1: "Run Act 1: Prompt injection",
  act2: "Run Act 2: 3-shot structuring",
  act3: "Run Act 3: Two-agent reserve race",
} as const;

export const PUBLIC_SIGNAL_NAMES = [
  "policyRoot",
  "prevCommitment",
  "newCommitment",
  "recipient",
  "amount",
  "epoch",
  "invoiceHash",
] as const;

export function sandboxIdOf(url: string): string {
  return new URL(url).searchParams.get("sandbox") ?? "";
}

interface ServerState {
  readonly receipts: readonly { readonly provenance: { readonly status: string } }[];
  readonly mainnetExplorerLinks: readonly { readonly txExplorerUrl: string }[];
}

// Reads the sandbox straight from the API, so a test can wait for server-side work the page must ignore.
export async function serverStateOf(app: App, sandboxId: string): Promise<ServerState> {
  const response = await fetch(new URL(`/api/demo/state?sandbox=${sandboxId}`, app.baseUrl));
  return (await response.json()) as ServerState;
}
