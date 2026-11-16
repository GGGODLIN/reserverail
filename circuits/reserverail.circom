pragma circom 2.1.5;

include "poseidon.circom";
include "bitify.circom";
include "comparators.circom";
include "binary-merkle-root.circom";

template ReserveRail(ALLOWLIST_DEPTH) {
    signal input policyRoot;
    signal input prevCommitment;
    signal input newCommitment;
    signal input recipient;
    signal input amount;
    signal input epoch;
    signal input invoiceHash;

    signal input allowlistRoot;
    signal input allowlistPathIndices[ALLOWLIST_DEPTH];
    signal input allowlistSiblings[ALLOWLIST_DEPTH];
    signal input balance;
    signal input spentSoFar;
    signal input prevEpoch;
    signal input epochCap;
    signal input payrollFloor;
    signal input policySalt;
    signal input prevSalt;
    signal input newSalt;
    signal input invoiceIdField;

    // @rule UINT64_RANGE_CHECKS: Enforce 64-bit unsigned range on monetary and epoch inputs to block finite-field wraparound
    component amountBits = Num2Bits(64);
    amountBits.in <== amount;
    component spentBits = Num2Bits(64);
    spentBits.in <== spentSoFar;
    component balanceBits = Num2Bits(64);
    balanceBits.in <== balance;
    component floorBits = Num2Bits(64);
    floorBits.in <== payrollFloor;
    component capBits = Num2Bits(64);
    capBits.in <== epochCap;
    component epochBits = Num2Bits(64);
    epochBits.in <== epoch;
    component prevEpochBits = Num2Bits(64);
    prevEpochBits.in <== prevEpoch;
    // @end UINT64_RANGE_CHECKS

    // @rule ALLOWLIST_MERKLE_INCLUSION: Verify recipient leaf belongs to confidential Vendor Allowlist with binary path selectors
    component recipientLeaf = Poseidon(1);
    recipientLeaf.inputs[0] <== recipient;

    component allowlistMerkle = BinaryMerkleRoot(ALLOWLIST_DEPTH);
    allowlistMerkle.leaf <== recipientLeaf.out;
    allowlistMerkle.depth <== ALLOWLIST_DEPTH;
    for (var i = 0; i < ALLOWLIST_DEPTH; i++) {
        allowlistPathIndices[i] * (allowlistPathIndices[i] - 1) === 0;
        allowlistMerkle.indices[i] <== allowlistPathIndices[i];
        allowlistMerkle.siblings[i] <== allowlistSiblings[i];
    }
    allowlistMerkle.out === allowlistRoot;
    // @end ALLOWLIST_MERKLE_INCLUSION

    // @rule EPOCH_MONOTONICITY: Prevent stale epoch regression from resetting cumulative epoch spend backwards
    component epochNonDecreasing = LessEqThan(64);
    epochNonDecreasing.in[0] <== prevEpoch;
    epochNonDecreasing.in[1] <== epoch;
    epochNonDecreasing.out === 1;
    // @end EPOCH_MONOTONICITY

    // @rule EPOCH_SPEND_ACCUMULATION: Accumulate spentSoFar in same epoch or reset baseSpent to zero on epoch advance
    component isSameEpoch = IsEqual();
    isSameEpoch.in[0] <== epoch;
    isSameEpoch.in[1] <== prevEpoch;
    signal sameEpoch;
    sameEpoch <== isSameEpoch.out;
    signal baseSpent;
    baseSpent <== sameEpoch * spentSoFar;
    signal newSpent;
    newSpent <== baseSpent + amount;
    // @end EPOCH_SPEND_ACCUMULATION

    // @rule EPOCH_SPEND_CAP_BOUND: Pure-addition Epoch Spend Cap inequality (newSpent <= epochCap) over 65-bit sum domain
    component withinEpochCap = LessEqThan(65);
    withinEpochCap.in[0] <== newSpent;
    withinEpochCap.in[1] <== epochCap;
    withinEpochCap.out === 1;
    // @end EPOCH_SPEND_CAP_BOUND

    // @rule PAYROLL_RESERVE_FLOOR_BOUND: Pure-addition Payroll Reserve Floor inequality (newSpent + payrollFloor <= balance) over 66-bit sum domain
    component withinReserveFloor = LessEqThan(66);
    withinReserveFloor.in[0] <== newSpent + payrollFloor;
    withinReserveFloor.in[1] <== balance;
    withinReserveFloor.out === 1;
    // @end PAYROLL_RESERVE_FLOOR_BOUND

    // @rule POLICY_COMMITMENT_BINDING: Bind confidential Vendor Allowlist root, Epoch Spend Cap, and Payroll Reserve Floor to policyRoot
    component policyHasher = Poseidon(4);
    policyHasher.inputs[0] <== allowlistRoot;
    policyHasher.inputs[1] <== epochCap;
    policyHasher.inputs[2] <== payrollFloor;
    policyHasher.inputs[3] <== policySalt;
    policyRoot === policyHasher.out;
    // @end POLICY_COMMITMENT_BINDING

    // @rule PREV_COMMITMENT_BINDING: Bind prior confidential balance, spentSoFar, and prevEpoch to C_old (prevCommitment)
    component prevHasher = Poseidon(4);
    prevHasher.inputs[0] <== balance;
    prevHasher.inputs[1] <== spentSoFar;
    prevHasher.inputs[2] <== prevEpoch;
    prevHasher.inputs[3] <== prevSalt;
    prevCommitment === prevHasher.out;
    // @end PREV_COMMITMENT_BINDING

    // @rule NEW_COMMITMENT_BINDING: Bind updated newSpent and epoch to deterministic C_new (newCommitment)
    component newHasher = Poseidon(4);
    newHasher.inputs[0] <== balance;
    newHasher.inputs[1] <== newSpent;
    newHasher.inputs[2] <== epoch;
    newHasher.inputs[3] <== newSalt;
    newCommitment === newHasher.out;
    // @end NEW_COMMITMENT_BINDING

    // @rule INVOICE_HASH_BINDING: Bind public Invoice Digest to recipient and invoiceIdField
    component invoiceHasher = Poseidon(2);
    invoiceHasher.inputs[0] <== recipient;
    invoiceHasher.inputs[1] <== invoiceIdField;
    invoiceHash === invoiceHasher.out;
    // @end INVOICE_HASH_BINDING
}

component main {public [policyRoot, prevCommitment, newCommitment, recipient, amount, epoch, invoiceHash]} = ReserveRail(10);
