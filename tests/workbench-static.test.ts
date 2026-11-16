import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import { terminateCurve } from "../src/circuit/prover.ts";
import { createReserveRailServer } from "../src/server/app.ts";

after(async () => {
  await terminateCurve();
});

interface RawResponse {
  readonly status: number;
  readonly contentType: string;
  readonly body: string;
}

// fetch() normalizes "..", so traversal attempts go out on a raw socket exactly as written.
function rawGet(port: number, requestPath: string): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method: "GET" }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => {
        body += chunk;
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, contentType: res.headers["content-type"] ?? "", body }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("Ticket 03 workbench static serving", () => {
  it("serves the built workbench from webRoot and never a file outside it", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rr-web-"));
    const webRoot = path.join(dir, "web");
    fs.mkdirSync(path.join(webRoot, "assets"), { recursive: true });
    fs.writeFileSync(path.join(webRoot, "index.html"), "<!doctype html><title>workbench-index</title>");
    fs.writeFileSync(path.join(webRoot, "assets", "app.js"), "console.info('workbench-asset');");
    const outsideSecret = "outside-webroot-synthetic-marker";
    fs.writeFileSync(path.join(dir, "secret.html"), outsideSecret);

    const srv = await createReserveRailServer({ dbPath: path.join(dir, "static.db"), webRoot });
    try {
      await srv.listen(0, "127.0.0.1");

      const index = await rawGet(srv.port, "/?sandbox=sbx_static_check");
      assert.equal(index.status, 200);
      assert.match(index.contentType, /^text\/html/);
      assert.ok(index.body.includes("workbench-index"));

      const asset = await rawGet(srv.port, "/assets/app.js");
      assert.equal(asset.status, 200);
      assert.match(asset.contentType, /^text\/javascript/);
      assert.ok(asset.body.includes("workbench-asset"));

      // The marker sits next to webRoot with a servable extension, so only the containment check keeps it out.
      assert.equal(fs.readFileSync(path.join(dir, "secret.html"), "utf8"), outsideSecret);
      for (const attempt of ["/../secret.html", "/%2e%2e/secret.html", "/assets/%2e%2e%2f%2e%2e%2fsecret.html", "/%2e%2e%5csecret.html"]) {
        const escaped = await rawGet(srv.port, attempt);
        assert.equal(escaped.status, 404, `${attempt} should not be served`);
        assert.equal(escaped.body.includes(outsideSecret), false, `${attempt} leaked a file outside webRoot`);
      }

      const api = await rawGet(srv.port, "/api/unknown-route");
      assert.equal(api.status, 404);
      assert.match(api.contentType, /^application\/json/);
    } finally {
      await srv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
