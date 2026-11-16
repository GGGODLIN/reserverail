import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { web } from "@e2e-dev/web";
import type { E2EConfig } from "e2e";

const repoRoot = import.meta.dirname;

// node:sqlite will not create missing parent directories for the per-target databases.
mkdirSync(resolve(repoRoot, ".e2e/db"), { recursive: true });

function workbenchServer(name: string, entry: string) {
  return {
    name,
    engine: web({ viewport: { width: 1440, height: 900 } }),
    app: {
      url: "http://127.0.0.1:0",
      readyUrl: "http://127.0.0.1:{port}/healthz",
      environment: "test",
      command: {
        executable: process.execPath,
        args: ["--experimental-strip-types", "--disable-warning=ExperimentalWarning", entry],
        cwd: repoRoot,
        // The runner passes no other environment, so no relay credentials can reach these servers.
        env: { PORT: "{port}", HOST: "127.0.0.1", RESERVERAIL_DB_PATH: `.e2e/db/${name}.db` },
        startupTimeout: 60_000,
        log: `.e2e/logs/${name}-app.log`,
      },
    },
  } as const;
}

export default {
  targets: [
    // Production entry without credentials: every receipt is DETERMINISTIC_REPLAY.
    workbenchServer("replay", "src/server/start.ts"),
    // Same server with a simulated Kurier relay, so LIVE finality streams without a key or network.
    workbenchServer("live-sim", "tests/e2e/support/live-sim-server.ts"),
  ],
  tests: "tests/e2e/**/*.e2e.ts",
  workers: 1,
  retries: 0,
  timeout: 90_000,
  assertionTimeout: 5_000,
  cache: "off",
  trace: "retain-on-failure",
  video: "off",
  reporters: ["list"],
} satisfies E2EConfig;
