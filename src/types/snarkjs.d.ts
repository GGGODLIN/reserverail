declare module "snarkjs" {
  export interface Groth16Proof {
    readonly pi_a: readonly string[];
    readonly pi_b: readonly (readonly string[])[];
    readonly pi_c: readonly string[];
    readonly protocol: string;
    readonly curve: string;
  }

  export interface Groth16VerificationKey {
    readonly protocol: string;
    readonly curve: string;
    readonly nPublic: number;
    readonly vk_alpha_1: readonly string[];
    readonly vk_beta_2: readonly (readonly string[])[];
    readonly vk_gamma_2: readonly (readonly string[])[];
    readonly vk_delta_2: readonly (readonly string[])[];
    readonly vk_alphabeta_12?: readonly (readonly (readonly string[])[])[];
    readonly IC: readonly (readonly string[])[];
  }

  export interface WtnsCalcOptions {
    readonly sanityCheck?: boolean;
    readonly memorySize?: number;
  }

  export interface R1csInfoResult {
    readonly n8: number;
    readonly prime: bigint;
    readonly nVars: number;
    readonly nOutputs: number;
    readonly nPubInputs: number;
    readonly nPrvInputs: number;
    readonly nLabels: number;
    readonly nConstraints: number;
    readonly useCustomGates?: boolean;
  }

  export type SnarkJsLogger = {
    info?: (...args: unknown[]) => void;
    warn?: (...args: unknown[]) => void;
    error?: (...args: unknown[]) => void;
    debug?: (...args: unknown[]) => void;
  };

  export type BinarySinkOrSource =
    | string
    | Uint8Array
    | {
        type: "mem";
        data?: Uint8Array;
      };

  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasmFile: BinarySinkOrSource,
      zkeyFileName: BinarySinkOrSource,
      logger?: SnarkJsLogger,
      wtnsCalcOptions?: WtnsCalcOptions,
      proverOptions?: Record<string, unknown>,
    ): Promise<{
      proof: Groth16Proof;
      publicSignals: string[];
    }>;
    verify(
      vkVerifier: Groth16VerificationKey,
      publicSignals: readonly string[],
      proof: Groth16Proof,
      logger?: SnarkJsLogger,
    ): Promise<boolean>;
  };

  export const wtns: {
    calculate(
      input: Record<string, unknown>,
      wasmFileName: BinarySinkOrSource,
      wtnsFileName: BinarySinkOrSource,
      options?: WtnsCalcOptions,
    ): Promise<void>;
    exportJson(wtnsFileName: BinarySinkOrSource): Promise<bigint[]>;
  };

  export const r1cs: {
    info(r1csName: BinarySinkOrSource, logger?: SnarkJsLogger): Promise<R1csInfoResult>;
  };

  export const zKey: {
    newZKey(
      r1csName: BinarySinkOrSource,
      ptauName: BinarySinkOrSource,
      zkeyName: BinarySinkOrSource,
      logger?: SnarkJsLogger,
    ): Promise<Uint8Array>;
    contribute(
      zkeyNameOld: BinarySinkOrSource,
      zkeyNameNew: BinarySinkOrSource,
      name: string,
      entropy: string,
      logger?: SnarkJsLogger,
    ): Promise<Uint8Array>;
    exportVerificationKey(
      zkeyName: BinarySinkOrSource,
      logger?: SnarkJsLogger,
    ): Promise<Groth16VerificationKey>;
  };
}

declare var curve_bn128:
  | {
      terminate: () => Promise<void>;
    }
  | undefined;
