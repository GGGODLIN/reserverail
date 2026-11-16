import { terminateCurve } from "../circuit/prover.ts";
import { createReserveRailServer } from "./app.ts";

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "127.0.0.1";

const server = await createReserveRailServer({
  dbPath: process.env.RESERVERAIL_DB_PATH ?? "reserverail.db",
});

await server.listen(port, host);
process.stdout.write(`${JSON.stringify({ event: "server.listening", url: server.url })}\n`);

process.on("SIGINT", () => {
  void (async () => {
    await server.close();
    await terminateCurve();
    process.exit(0);
  })();
});

process.on("SIGTERM", () => {
  void (async () => {
    await server.close();
    await terminateCurve();
    process.exit(0);
  })();
});
