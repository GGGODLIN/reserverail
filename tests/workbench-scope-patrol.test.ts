import assert from "node:assert/strict";
import { describe, it } from "node:test";
import fc from "fast-check";
import {
  acceptError,
  acceptRun,
  acceptSnapshot,
  createScopedView,
  enterScope,
  ticketOf,
} from "../web/src/model/workbench-model.ts";
import type { ScopeTicket, ScopedView } from "../web/src/model/workbench-model.ts";

// Tier 2 patrol of the workbench scope machine: Reset and scope switches race in-flight
// state fetches, act/proposal runs and failures. Every payload records the generation it was
// issued under, which is the independent oracle for "nothing stale is ever displayed".
interface Snapshot {
  readonly sandboxId: string;
  readonly issuedGeneration: number;
}

interface Run {
  readonly issuedGeneration: number;
}

type View = ScopedView<Snapshot, Run>;

type ScopeEvent =
  | { readonly kind: "reset" }
  | { readonly kind: "switch" }
  | { readonly kind: "issue" }
  | {
      readonly kind: "deliver";
      readonly pick: number;
      readonly payload: "snapshot" | "run" | "error";
      readonly foreignSandbox: boolean;
    };

interface Reducers {
  readonly enterScope: (view: View, sandboxId: string | null) => View;
  readonly acceptSnapshot: (view: View, ticket: ScopeTicket, snapshot: Snapshot) => View;
  readonly acceptRun: (view: View, ticket: ScopeTicket, run: Run) => View;
  readonly acceptError: (view: View, ticket: ScopeTicket, message: string) => View;
}

const REAL: Reducers = { enterScope, acceptSnapshot, acceptRun, acceptError };

interface PatrolState {
  view: View;
  pending: ScopeTicket[];
  expectedGeneration: number;
  assigned: number;
}

interface Verdict {
  readonly p1NothingStale: boolean;
  readonly p2SnapshotMatchesScope: boolean;
  readonly p3CurrentUpdatesLand: boolean;
  readonly p4GenerationMonotonic: boolean;
}

const ALL_HOLD = (verdict: Verdict): boolean =>
  verdict.p1NothingStale && verdict.p2SnapshotMatchesScope && verdict.p3CurrentUpdatesLand && verdict.p4GenerationMonotonic;

function errorGeneration(message: string | null): number | null {
  return message === null ? null : Number(message.split("@")[1]);
}

function step(state: PatrolState, event: ScopeEvent, reducers: Reducers): Verdict {
  let p3 = true;
  if (event.kind === "reset") {
    state.view = reducers.enterScope(state.view, state.view.sandboxId);
    state.expectedGeneration += 1;
  } else if (event.kind === "switch") {
    state.view = reducers.enterScope(state.view, null);
    state.expectedGeneration += 1;
  } else if (event.kind === "issue") {
    state.pending.push(ticketOf(state.view));
  } else if (state.pending.length > 0) {
    const [ticket] = state.pending.splice(event.pick % state.pending.length, 1);
    if (ticket !== undefined) {
      const current = ticket.generation === state.view.generation;
      if (event.payload === "snapshot") {
        state.assigned += 1;
        const assignedId = ticket.sandboxId ?? `sbx_assigned_${state.assigned}`;
        const sandboxId = event.foreignSandbox ? `sbx_foreign_${state.assigned}` : assignedId;
        const snapshot = { sandboxId, issuedGeneration: ticket.generation };
        state.view = reducers.acceptSnapshot(state.view, ticket, snapshot);
        const fitsScope = state.view.sandboxId === sandboxId;
        if (current && !event.foreignSandbox) {
          p3 = state.view.snapshot === snapshot && fitsScope;
        }
      } else if (event.payload === "run") {
        const run = { issuedGeneration: ticket.generation };
        state.view = reducers.acceptRun(state.view, ticket, run);
        if (current) {
          p3 = state.view.run === run;
        }
      } else {
        state.view = reducers.acceptError(state.view, ticket, `failed@${ticket.generation}`);
        if (current) {
          p3 = errorGeneration(state.view.error) === ticket.generation;
        }
      }
    }
  }
  const { view } = state;
  return {
    p1NothingStale:
      (view.snapshot === null || view.snapshot.issuedGeneration === view.generation) &&
      (view.run === null || view.run.issuedGeneration === view.generation) &&
      (view.error === null || errorGeneration(view.error) === view.generation),
    p2SnapshotMatchesScope: view.snapshot === null || view.snapshot.sandboxId === view.sandboxId,
    p3CurrentUpdatesLand: p3,
    p4GenerationMonotonic: view.generation === state.expectedGeneration,
  };
}

function patrol(events: readonly ScopeEvent[], reducers: Reducers): Verdict[] {
  const state: PatrolState = {
    view: createScopedView<Snapshot, Run>("sbx_initial"),
    pending: [],
    expectedGeneration: 0,
    assigned: 0,
  };
  return events.map((event) => step(state, event, reducers));
}

const eventArb: fc.Arbitrary<ScopeEvent> = fc.oneof(
  fc.constant({ kind: "reset" } as const),
  fc.constant({ kind: "switch" } as const),
  fc.constant({ kind: "issue" } as const),
  fc.record({
    kind: fc.constant("deliver" as const),
    pick: fc.nat({ max: 7 }),
    payload: fc.constantFrom("snapshot" as const, "run" as const, "error" as const),
    foreignSandbox: fc.boolean(),
  }),
);

describe("Ticket 03 Tier 2 patrol: scope generations against in-flight updates", () => {
  it("over 1-40 interleaved resets, switches, requests and late deliveries, nothing stale is shown and current updates land", () => {
    let staleDeliveries = 0;
    let currentDeliveries = 0;
    fc.assert(
      fc.property(fc.array(eventArb, { minLength: 1, maxLength: 40 }), (events) => {
        const state: PatrolState = {
          view: createScopedView<Snapshot, Run>("sbx_initial"),
          pending: [],
          expectedGeneration: 0,
          assigned: 0,
        };
        for (const event of events) {
          if (event.kind === "deliver" && state.pending.length > 0) {
            const ticket = state.pending[event.pick % state.pending.length];
            if (ticket !== undefined && ticket.generation === state.view.generation) {
              currentDeliveries += 1;
            } else {
              staleDeliveries += 1;
            }
          }
          if (!ALL_HOLD(step(state, event, REAL))) {
            return false;
          }
        }
        return true;
      }),
      { numRuns: 400 },
    );
    // Reachability: the runs did exercise both late (stale) and current deliveries.
    assert.ok(staleDeliveries > 0, "no stale delivery was generated");
    assert.ok(currentDeliveries > 0, "no current delivery was generated");
  });

  it("calibration: each invariant fails on its own against a reducer that skips the matching guard", () => {
    const lateSnapshotAfterReset: ScopeEvent[] = [
      { kind: "issue" },
      { kind: "reset" },
      { kind: "deliver", pick: 0, payload: "snapshot", foreignSandbox: false },
    ];
    const ignoresGeneration: Reducers = {
      ...REAL,
      acceptSnapshot: (view, _ticket, snapshot) => ({ ...view, sandboxId: snapshot.sandboxId, snapshot }),
    };
    assert.equal(patrol(lateSnapshotAfterReset, ignoresGeneration).at(-1)?.p1NothingStale, false);
    assert.equal(patrol(lateSnapshotAfterReset, REAL).at(-1)?.p1NothingStale, true);

    const foreignSnapshot: ScopeEvent[] = [
      { kind: "issue" },
      { kind: "deliver", pick: 0, payload: "snapshot", foreignSandbox: true },
    ];
    const ignoresSandbox: Reducers = {
      ...REAL,
      acceptSnapshot: (view, ticket, snapshot) =>
        ticket.generation === view.generation ? { ...view, snapshot } : view,
    };
    assert.equal(patrol(foreignSnapshot, ignoresSandbox).at(-1)?.p2SnapshotMatchesScope, false);
    assert.equal(patrol(foreignSnapshot, REAL).at(-1)?.p2SnapshotMatchesScope, true);

    const currentRun: ScopeEvent[] = [{ kind: "issue" }, { kind: "deliver", pick: 0, payload: "run", foreignSandbox: false }];
    const dropsEverything: Reducers = { ...REAL, acceptRun: (view) => view };
    assert.equal(patrol(currentRun, dropsEverything).at(-1)?.p3CurrentUpdatesLand, false);
    assert.equal(patrol(currentRun, REAL).at(-1)?.p3CurrentUpdatesLand, true);

    const keepsGeneration: Reducers = {
      ...REAL,
      enterScope: (view, sandboxId) => ({ ...view, sandboxId, snapshot: null, run: null, error: null }),
    };
    assert.equal(patrol(lateSnapshotAfterReset, keepsGeneration).at(-1)?.p4GenerationMonotonic, false);
    assert.equal(patrol(lateSnapshotAfterReset, REAL).at(-1)?.p4GenerationMonotonic, true);
  });
});
