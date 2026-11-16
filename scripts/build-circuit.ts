import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import type { CircuitRuleId, CircuitRuleLocation, ReserveRailPublicSignalName } from "../src/generated/circuit-abi.ts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CIRCUIT_REL_PATH = "circuits/reserverail.circom";
const CIRCUIT_ABS_PATH = path.join(REPO_ROOT, CIRCUIT_REL_PATH);
const ARTIFACTS_DIR = path.join(REPO_ROOT, "artifacts");
const GENERATED_ABI_PATH = path.join(REPO_ROOT, "src", "generated", "circuit-abi.ts");

const EXPECTED_PUBLIC_SIGNALS: readonly ReserveRailPublicSignalName[] = [
  "policyRoot",
  "prevCommitment",
  "newCommitment",
  "recipient",
  "amount",
  "epoch",
  "invoiceHash",
];

const RULE_COMPONENT_PREFIXES: Readonly<Record<CircuitRuleId, readonly string[]>> = {
  UINT64_RANGE_CHECKS: [
    "main.amountBits",
    "main.spentBits",
    "main.balanceBits",
    "main.floorBits",
    "main.capBits",
    "main.epochBits",
    "main.prevEpochBits",
  ],
  ALLOWLIST_MERKLE_INCLUSION: ["main.recipientLeaf", "main.allowlistMerkle"],
  EPOCH_MONOTONICITY: ["main.epochNonDecreasing"],
  EPOCH_SPEND_ACCUMULATION: ["main.isSameEpoch", "main.sameEpoch", "main.baseSpent", "main.newSpent"],
  EPOCH_SPEND_CAP_BOUND: ["main.withinEpochCap"],
  PAYROLL_RESERVE_FLOOR_BOUND: ["main.withinReserveFloor"],
  POLICY_COMMITMENT_BINDING: ["main.policyHasher"],
  PREV_COMMITMENT_BINDING: ["main.prevHasher"],
  NEW_COMMITMENT_BINDING: ["main.newHasher"],
  INVOICE_HASH_BINDING: ["main.invoiceHasher"],
};

function isPublicSignalName(name: string): name is ReserveRailPublicSignalName {
  return (EXPECTED_PUBLIC_SIGNALS as readonly string[]).includes(name);
}

function isRuleId(id: string): id is CircuitRuleId {
  return Object.prototype.hasOwnProperty.call(RULE_COMPONENT_PREFIXES, id);
}

async function ensurePtauFile(power: 13 | 14, cacheDir: string): Promise<string> {
  fs.mkdirSync(cacheDir, { recursive: true });
  const fileName = `ppot_0080_${power}.ptau`;
  const targetPath = path.join(cacheDir, fileName);
  if (fs.existsSync(targetPath) && fs.statSync(targetPath).size > 1_000_000) {
    return targetPath;
  }

  const url = `https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/${fileName}`;
  const tempDownloadPath = `${targetPath}.part-${process.pid}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to download PSE ptau (${response.status}) from ${url}`);
  }

  const rawBuffer = Buffer.from(await response.arrayBuffer());
  fs.writeFileSync(tempDownloadPath, rawBuffer);
  fs.renameSync(tempDownloadPath, targetPath);
  return targetPath;
}

function parseSymWireOrderAndRuleSymbols(
  symContent: string,
  nPublic: number,
): {
  readonly orderedPublicSignals: ReserveRailPublicSignalName[];
  readonly ruleSymbols: Readonly<Record<CircuitRuleId, string[]>>;
} {
  const wireToName = new Map<number, ReserveRailPublicSignalName>();
  const ruleSymbolSets: Record<CircuitRuleId, Set<string>> = {
    UINT64_RANGE_CHECKS: new Set(),
    ALLOWLIST_MERKLE_INCLUSION: new Set(),
    EPOCH_MONOTONICITY: new Set(),
    EPOCH_SPEND_ACCUMULATION: new Set(),
    EPOCH_SPEND_CAP_BOUND: new Set(),
    PAYROLL_RESERVE_FLOOR_BOUND: new Set(),
    POLICY_COMMITMENT_BINDING: new Set(),
    PREV_COMMITMENT_BINDING: new Set(),
    NEW_COMMITMENT_BINDING: new Set(),
    INVOICE_HASH_BINDING: new Set(),
  };

  for (const rawLine of symContent.split("\n")) {
    const line = rawLine.trim();
    if (line.length === 0) {
      continue;
    }
    const parts = line.split(",");
    if (parts.length < 4) {
      continue;
    }
    const witnessIdx = Number.parseInt(parts[1] ?? "", 10);
    const componentIdx = Number.parseInt(parts[2] ?? "", 10);
    const symbolName = parts.slice(3).join(",");

    const topMatch = /^main\.([A-Za-z0-9_]+)$/.exec(symbolName);
    if (
      topMatch !== null &&
      witnessIdx >= 1 &&
      witnessIdx <= nPublic &&
      isPublicSignalName(topMatch[1] ?? "")
    ) {
      wireToName.set(witnessIdx, topMatch[1] as ReserveRailPublicSignalName);
    }

    for (const ruleId of Object.keys(RULE_COMPONENT_PREFIXES) as CircuitRuleId[]) {
      const prefixes = RULE_COMPONENT_PREFIXES[ruleId];
      if (
        prefixes.some(
          (prefix) => symbolName === prefix || symbolName.startsWith(`${prefix}.`) || symbolName.startsWith(`${prefix}[`),
        )
      ) {
        const bucket = ruleSymbolSets[ruleId];
        if (bucket.size < 8) {
          bucket.add(symbolName);
        }
      }
    }
  }

  const orderedPublicSignals: ReserveRailPublicSignalName[] = [];
  for (let wire = 1; wire <= nPublic; wire += 1) {
    const found = wireToName.get(wire);
    if (found === undefined) {
      throw new Error(`Missing top-level public signal symbol for wire index ${wire}`);
    }
    orderedPublicSignals.push(found);
  }

  if (new Set(orderedPublicSignals).size !== EXPECTED_PUBLIC_SIGNALS.length) {
    throw new Error(`Public signal set mismatch: ${JSON.stringify(orderedPublicSignals)}`);
  }

  const ruleSymbols = Object.fromEntries(
    (Object.keys(ruleSymbolSets) as CircuitRuleId[]).map((id) => [id, [...ruleSymbolSets[id]]]),
  ) as Record<CircuitRuleId, string[]>;

  return { orderedPublicSignals, ruleSymbols };
}

function parseCircuitRuleLineMap(
  circomSource: string,
  ruleSymbols: Readonly<Record<CircuitRuleId, string[]>>,
): Record<CircuitRuleId, CircuitRuleLocation> {
  if (/\blog\s*\(/.test(circomSource)) {
    throw new Error("Security check failed: log() call detected inside circuits/reserverail.circom");
  }

  const lines = circomSource.split("\n");
  const openRule = new Map<CircuitRuleId, { readonly startLine: number; readonly description: string }>();
  const locations: Partial<Record<CircuitRuleId, CircuitRuleLocation>> = {};

  for (let idx = 0; idx < lines.length; idx += 1) {
    const lineNo = idx + 1;
    const text = lines[idx] ?? "";
    const startMatch = /\/\/\s*@rule\s+([A-Z0-9_]+):\s*(.+)$/.exec(text);
    if (startMatch !== null) {
      const rawId = startMatch[1] ?? "";
      const description = (startMatch[2] ?? "").trim();
      if (!isRuleId(rawId)) {
        throw new Error(`Unknown @rule identifier ${rawId} at line ${lineNo}`);
      }
      openRule.set(rawId, { startLine: lineNo, description });
      continue;
    }

    const endMatch = /\/\/\s*@end\s+([A-Z0-9_]+)\s*$/.exec(text);
    if (endMatch !== null) {
      const rawId = endMatch[1] ?? "";
      if (!isRuleId(rawId)) {
        throw new Error(`Unknown @end identifier ${rawId} at line ${lineNo}`);
      }
      const opened = openRule.get(rawId);
      if (opened === undefined) {
        throw new Error(`Unmatched @end ${rawId} at line ${lineNo}`);
      }
      locations[rawId] = {
        ruleId: rawId,
        file: CIRCUIT_REL_PATH,
        startLine: opened.startLine,
        endLine: lineNo,
        description: opened.description,
        symbols: ruleSymbols[rawId],
      };
      openRule.delete(rawId);
    }
  }

  for (const requiredId of Object.keys(RULE_COMPONENT_PREFIXES) as CircuitRuleId[]) {
    if (locations[requiredId] === undefined) {
      throw new Error(`Missing @rule/${requiredId} annotation in ${CIRCUIT_REL_PATH}`);
    }
  }

  return locations as Record<CircuitRuleId, CircuitRuleLocation>;
}

export function renderGeneratedCircuitAbiSource(params: {
  readonly constraintCount: number;
  readonly orderedPublicSignals: readonly ReserveRailPublicSignalName[];
  readonly lineMap: Readonly<Record<CircuitRuleId, CircuitRuleLocation>>;
  readonly verificationKey: unknown;
  readonly registeredVkHash: string;
}): string {
  const signalUnionLines = params.orderedPublicSignals.map((s) => `  | "${s}"`).join("\n");
  const signalInterfaceLines = params.orderedPublicSignals
    .map((s) => `  readonly ${s}: bigint;`)
    .join("\n");
  const decodeEntries = params.orderedPublicSignals
    .map((s, idx) => `    ${s}: parseFieldSignal(rawSignals[${idx}], "${s}"),`)
    .join("\n");
  const encodeEntries = params.orderedPublicSignals
    .map((s) => `    formatFieldSignal(signals.${s}, "${s}"),`)
    .join("\n");

  return `// Auto-generated by scripts/build-circuit.ts — DO NOT EDIT MANUALLY
import type { Groth16VerificationKey } from "snarkjs";

export const SNARK_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const ALLOWLIST_TREE_DEPTH = 10 as const;

export const CIRCUIT_CONSTRAINT_COUNT = ${params.constraintCount} as const;

export type ReserveRailPublicSignalName =
${signalUnionLines};

export interface ReserveRailPublicSignals {
${signalInterfaceLines}
}

export type CircuitRuleId =
  | "UINT64_RANGE_CHECKS"
  | "ALLOWLIST_MERKLE_INCLUSION"
  | "EPOCH_MONOTONICITY"
  | "EPOCH_SPEND_ACCUMULATION"
  | "EPOCH_SPEND_CAP_BOUND"
  | "PAYROLL_RESERVE_FLOOR_BOUND"
  | "POLICY_COMMITMENT_BINDING"
  | "PREV_COMMITMENT_BINDING"
  | "NEW_COMMITMENT_BINDING"
  | "INVOICE_HASH_BINDING";

export interface CircuitRuleLocation {
  readonly ruleId: CircuitRuleId;
  readonly file: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly description: string;
  readonly symbols: readonly string[];
}

export const PUBLIC_SIGNAL_NAMES: readonly ReserveRailPublicSignalName[] = ${JSON.stringify(
    params.orderedPublicSignals,
    null,
    2,
  )} as const;

export const CIRCUIT_RULE_LINE_MAP: Readonly<Record<CircuitRuleId, CircuitRuleLocation>> = ${JSON.stringify(
    params.lineMap,
    null,
    2,
  )};

export const VERIFICATION_KEY: Groth16VerificationKey = ${JSON.stringify(
    params.verificationKey,
    null,
    2,
  )};

export const REGISTERED_VK_HASH: string = ${JSON.stringify(params.registeredVkHash)};

function parseFieldSignal(raw: string | bigint | undefined, name: string): bigint {
  if (raw === undefined) {
    throw new RangeError(\`Missing public signal "\${name}"\`);
  }
  const value = typeof raw === "bigint" ? raw : BigInt(raw);
  if (value < 0n || value >= SNARK_SCALAR_FIELD) {
    throw new RangeError(\`Public signal "\${name}" is outside bn128 scalar field\`);
  }
  return value;
}

function formatFieldSignal(value: bigint, name: string): string {
  if (typeof value !== "bigint" || value < 0n || value >= SNARK_SCALAR_FIELD) {
    throw new RangeError(\`Public signal "\${name}" is outside bn128 scalar field\`);
  }
  return value.toString(10);
}

export function toPublicSignalsArray(signals: ReserveRailPublicSignals): string[] {
  return [
${encodeEntries}
  ];
}

export function fromPublicSignalsArray(
  rawSignals: readonly (string | bigint)[],
): ReserveRailPublicSignals {
  if (rawSignals.length !== ${params.orderedPublicSignals.length}) {
    throw new RangeError(
      \`Expected publicSignals length ${params.orderedPublicSignals.length}, received \${rawSignals.length}\`,
    );
  }
  return {
${decodeEntries}
  };
}
`;
}

async function buildCircuit(): Promise<void> {
  const circomBin = process.env.CIRCOM_BIN ?? "circom";
  const ptauCacheDir =
    process.env.PTAU_CACHE_DIR ?? path.join(os.tmpdir(), "reserverail-ptau-cache");
  const buildTempDir = fs.mkdtempSync(path.join(os.tmpdir(), "reserverail-circom-build-"));

  try {
    execFileSync(
      circomBin,
      [
        CIRCUIT_ABS_PATH,
        "--r1cs",
        "--wasm",
        "--sym",
        "-l",
        path.join(REPO_ROOT, "node_modules", "circomlib", "circuits"),
        "-l",
        path.join(REPO_ROOT, "node_modules", "@zk-kit", "circuits", "circom"),
        "-o",
        buildTempDir,
      ],
      { stdio: "pipe" },
    );

    const r1csPath = path.join(buildTempDir, "reserverail.r1cs");
    const symPath = path.join(buildTempDir, "reserverail.sym");
    const wasmBuiltPath = path.join(buildTempDir, "reserverail_js", "reserverail.wasm");

    const r1csInfo = await snarkjs.r1cs.info(r1csPath);
    if (r1csInfo.nConstraints <= 0 || r1csInfo.nConstraints > 16_384) {
      throw new Error(
        `Constraint budget violated: ${r1csInfo.nConstraints} constraints (must be in 1..16384)`,
      );
    }

    const requiredDomain = r1csInfo.nConstraints + r1csInfo.nPubInputs + r1csInfo.nOutputs + 1;
    const ptauPower: 13 | 14 = requiredDomain <= 8_192 ? 13 : 14;
    const ptauPath = await ensurePtauFile(ptauPower, ptauCacheDir);

    const zkey0Path = path.join(buildTempDir, "reserverail_0000.zkey");
    const finalZkeyTempPath = path.join(buildTempDir, "reserverail_final.zkey");
    const entropy = crypto.randomBytes(32).toString("hex");

    await snarkjs.zKey.newZKey(r1csPath, ptauPath, zkey0Path);
    await snarkjs.zKey.contribute(
      zkey0Path,
      finalZkeyTempPath,
      "reserverail-groth16-phase2",
      entropy,
    );
    const verificationKey = await snarkjs.zKey.exportVerificationKey(finalZkeyTempPath);

    const symContent = fs.readFileSync(symPath, "utf8");
    const { orderedPublicSignals, ruleSymbols } = parseSymWireOrderAndRuleSymbols(
      symContent,
      verificationKey.nPublic,
    );
    const circomSource = fs.readFileSync(CIRCUIT_ABS_PATH, "utf8");
    const lineMap = parseCircuitRuleLineMap(circomSource, ruleSymbols);

    fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
    fs.copyFileSync(wasmBuiltPath, path.join(ARTIFACTS_DIR, "reserverail.wasm"));
    fs.copyFileSync(finalZkeyTempPath, path.join(ARTIFACTS_DIR, "reserverail_final.zkey"));
    fs.writeFileSync(
      path.join(ARTIFACTS_DIR, "verification_key.json"),
      `${JSON.stringify(verificationKey, null, 2)}\n`,
      "utf8",
    );
    fs.writeFileSync(
      path.join(ARTIFACTS_DIR, "circuit-line-map.json"),
      `${JSON.stringify(
        {
          circuitFile: CIRCUIT_REL_PATH,
          constraintCount: r1csInfo.nConstraints,
          nPublic: verificationKey.nPublic,
          publicSignalWireOrder: orderedPublicSignals,
          ptauCeremonyFile: path.basename(ptauPath),
          rules: lineMap,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const abiSource = renderGeneratedCircuitAbiSource({
      constraintCount: r1csInfo.nConstraints,
      orderedPublicSignals,
      lineMap,
      verificationKey,
      registeredVkHash: "",
    });
    fs.writeFileSync(GENERATED_ABI_PATH, abiSource, "utf8");

    process.stdout.write(
      `${JSON.stringify({
        ok: true,
        constraintCount: r1csInfo.nConstraints,
        nVars: r1csInfo.nVars,
        nPublic: verificationKey.nPublic,
        ptauFile: path.basename(ptauPath),
        publicSignalWireOrder: orderedPublicSignals,
      })}\n`,
    );
  } finally {
    fs.rmSync(buildTempDir, { recursive: true, force: true });
    await globalThis.curve_bn128?.terminate();
    globalThis.curve_bn128 = undefined;
  }
}

const isDirectEntrypoint =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectEntrypoint) {
  await buildCircuit();
}
