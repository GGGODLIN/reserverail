import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { terminateCurve } from "../src/circuit/prover.ts";
import {
  DEFAULT_VENDORS,
  evaluatePolicyShadow,
  stringToFieldElement,
  verifyShadowAgainstWasm,
} from "../src/engine/policy.ts";
import { loadBaselineMainnetCassette } from "../src/engine/replay-cassette.ts";
import { ReserveRailStore } from "../src/engine/sqlite-store.ts";
import { CIRCUIT_CONSTRAINT_COUNT, REGISTERED_VK_HASH } from "../src/generated/circuit-abi.ts";
import { scrubKurierText } from "../src/kurier/kurier-client.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function parseDbPathArg(argv: readonly string[]): string {
  const idx = argv.indexOf("--db");
  if (idx >= 0 && argv[idx + 1] !== undefined) {
    return argv[idx + 1]!;
  }
  return process.env.RESERVERAIL_DB_PATH ?? path.join(REPO_ROOT, "reserverail.db");
}

function assertNoSecretLeak(output: string): void {
  const secretEnvNames = [
    "KURIER_API_KEY",
    "AGENT_GAMES_HMAC_SECRET",
    "AGENT_GAMES_HMAC_SECRET_PREVIOUS",
    "MARITACA_API_KEY",
    "AMD_TOKEN_LAB_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
  ];
  for (const name of secretEnvNames) {
    const val = process.env[name]?.trim() ?? "";
    if (val.length >= 6 && output.includes(val)) {
      throw new Error(`SECURITY CRITICAL: Secret from ${name} appeared in diagnostic output`);
    }
  }
}

async function main(): Promise<void> {
  const startedAt = performance.now();
  const dbPath = parseDbPathArg(process.argv.slice(2));
  const artifactsDir = path.join(REPO_ROOT, "artifacts");

  const requiredFiles = [
    "reserverail.wasm",
    "reserverail_final.zkey",
    "verification_key.json",
    "circuit-line-map.json",
    "gate01-mainnet-receipt.json",
  ];

  const missingArtifacts = requiredFiles.filter(
    (name) => !fs.existsSync(path.join(artifactsDir, name)),
  );

  let cassetteValid = false;
  let cassetteTxHash: string | null = null;
  if (!missingArtifacts.includes("gate01-mainnet-receipt.json")) {
    try {
      const cassette = loadBaselineMainnetCassette(
        path.join(artifactsDir, "gate01-mainnet-receipt.json"),
      );
      cassetteValid = cassette.vkHash === REGISTERED_VK_HASH;
      cassetteTxHash = cassette.validTransition.txHash;
    } catch {
      cassetteValid = false;
    }
  }

  let wasmDifferentialOk = false;
  if (!missingArtifacts.includes("reserverail.wasm")) {
    try {
      const shadow = evaluatePolicyShadow({
        allowlistRecipients: DEFAULT_VENDORS.map((v) => v.recipientField),
        epochCap: 50_000n,
        payrollFloor: 60_000n,
        policySalt: 101n,
        balance: 100_000n,
        spentSoFar: 0n,
        prevEpoch: 1n,
        prevSalt: 202n,
        recipient: DEFAULT_VENDORS[0]!.recipientField,
        amount: 12_000n,
        epoch: 1n,
        invoiceIdField: stringToFieldElement("diag-probe-1"),
        newSalt: 303n,
        knownInvoiceHashes: new Set(),
      });
      if (shadow.ok) {
        const diff = await verifyShadowAgainstWasm(shadow);
        wasmDifferentialOk = !diff.drift;
      }
    } catch {
      wasmDifferentialOk = false;
    }
  }

  const dbExists = fs.existsSync(dbPath);
  let dbSummary = {
    totalSandboxes: 0,
    demoSandboxes: 0,
    activeLeases: 0,
    outboxCounts: {
      PENDING_SUBMIT: 0,
      SUBMITTED: 0,
      INCLUDED_IN_BLOCK: 0,
      FINALIZED: 0,
      ROLLED_BACK: 0,
    },
    invariantDriftCount: 0,
    recentEvents: [] as ReadonlyArray<{
      readonly eventType: string;
      readonly detail: string;
      readonly createdAt: string;
    }>,
  };

  if (dbExists) {
    const store = ReserveRailStore.open(dbPath, {
      scrubKey: process.env.KURIER_API_KEY,
    });
    try {
      dbSummary = store.getDiagnosticsSummary();
    } finally {
      store.close();
    }
  }

  const healthy =
    missingArtifacts.length === 0 &&
    cassetteValid &&
    wasmDifferentialOk &&
    dbSummary.invariantDriftCount === 0;

  const report = {
    ok: healthy,
    elapsedMs: Math.round(performance.now() - startedAt),
    circuit: {
      constraintCount: CIRCUIT_CONSTRAINT_COUNT,
      vkHash: REGISTERED_VK_HASH,
      missingArtifacts,
      cassetteValid,
      cassetteTxHash,
      wasmDifferentialOk,
    },
    sqlite: {
      dbExists,
      ...dbSummary,
    },
    configFlags: {
      hasKurierKey: (process.env.KURIER_API_KEY?.trim().length ?? 0) > 0,
      hasAgentHmacSecret: (process.env.AGENT_GAMES_HMAC_SECRET?.trim().length ?? 0) > 0,
      hasMaritacaKey: (process.env.MARITACA_API_KEY?.trim().length ?? 0) > 0,
      hasAmdTokenLabKey: (process.env.AMD_TOKEN_LAB_API_KEY?.trim().length ?? 0) > 0,
    },
  };

  const serialized = scrubKurierText(
    JSON.stringify(report, null, 2),
    process.env.KURIER_API_KEY,
  );
  assertNoSecretLeak(serialized);
  process.stdout.write(`${serialized}\n`);
  if (!healthy) {
    process.exitCode = 1;
  }
}

try {
  await main();
} finally {
  await terminateCurve();
}
