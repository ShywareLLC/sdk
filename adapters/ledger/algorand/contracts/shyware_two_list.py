"""
Shyware two-list invariant -- Algorand smart contract (PyTeal / ARC-4).

This is a chain-enforced implementation: the four checks below run inside
the Algorand Virtual Machine on every validating node, exactly like the
reference Hyperledger Fabric chaincode's `submitTwoListWrite`. A client
cannot skip, spoof, or race these checks -- the app call fails at the
protocol level if any of them do not hold. This is deliberately NOT a
passive box store that a JS client polices from the outside.

Five operations (identical contract to every other LedgerInterface adapter
in this SDK -- see adapters/ledger/interface.js):

  1. submit_two_list_write   -- rejection predicate + sybil resistance +
                                 replay protection, then atomic L1+L2 write
  2. get_count               -- read-only; the JS adapter reads the count
                                 box directly via algod (no transaction),
                                 this on-chain method exists for on-chain
                                 composability / other contracts to call
  3. rescind_two_list_write  -- delete L1 + L2, decrement the shared count
  4. replace_two_list_write  -- delete old L1, rejection-predicate-checked
                                 new L1 write; L2 and count untouched
  5. commit_period_close     -- one-time-only per scopingId

Storage: Algorand BOX storage, not global/local state. Global/local state
is capped at 64 total key-value slots per app account and cannot hold an
unbounded number of scopingId x submissionId / scopingId x identityHash
records. Boxes have no such cap and are the correct primitive here.

Box key scheme -- every key is a 2-byte ASCII prefix + a 32-byte SHA-256
digest, so every box name is a fixed 34 bytes, comfortably under
Algorand's 64-byte box-name limit regardless of how long the caller's
scopingId / submissionId / identityHash strings are:

    L1 box   "L1" + sha256(scopingId || "|" || submissionId)
             value = payloadCommitment bytes
             (List 1: direction-free submission id folded into the key,
              payload as the value -- no participant identity anywhere
              in this box)

    L2 box   "L2" + sha256(scopingId || "|" || identityHash)
             value = single marker byte 0x01
             (List 2: identity hash folded into the key, a 1-byte
              marker as the value -- no submission id, no payload,
              anywhere in this box; this is the on-chain enforcement
              point for "List 2 carries no submission identifier or
              payload")

    Count    "CN" + sha256(scopingId)
             value = 8-byte big-endian uint64
             (shared L1/L2 counter for this scopingId; count-match is a
              structural consequence of submit/rescind always moving
              L1 and L2 together, never independently)

    Period   "PC" + sha256(scopingId)
             value = l1MerkleRoot(32) || l2MerkleRoot(32) || attestation
             one-time-only write, enforced by box_create's own
             already-exists signal

No box ever stores both a submissionId and an identityHash together, and
no box's key is ever derived from the other list's key material -- there
is no join key between L1 and L2 anywhere in this contract's state.

Compile:
    python3 shyware_two_list.py
writes shyware_two_list_approval.teal, shyware_two_list_clear.teal, and
shyware_two_list.arc4.json (the ARC-4 application spec the JS adapter's
ABI method selectors are built from).
"""

import json
import os

from pyteal import (
    abi,
    Approve,
    Assert,
    Bytes,
    BareCallActions,
    Btoi,
    Concat,
    Expr,
    Global,
    If,
    Int,
    Itob,
    Len,
    OnCompleteAction,
    OptimizeOptions,
    Router,
    ScratchVar,
    Seq,
    Sha256,
    TealType,
    compileTeal,
    Mode,
)
from pyteal.ast import App


# ---------------------------------------------------------------------------
# NamedTuple output helpers
#
# abi.NamedTuple fields (e.g. output.l1_count) are ComputedValue
# TupleElements -- they support store_into(), not .set(). To populate a
# NamedTuple output, build its component abi values and call the tuple's
# own .set(*components).
# ---------------------------------------------------------------------------

def set_uint64_bool(dest: "abi.NamedTuple", a: Expr, b: Expr, flag: Expr) -> Expr:
    """Set a 3-field (Uint64, Uint64, Bool) NamedTuple from raw TealType values."""
    av, bv, fv = abi.Uint64(), abi.Uint64(), abi.Bool()
    return Seq(av.set(a), bv.set(b), fv.set(flag), dest.set(av, bv, fv))


def set_bool_bool(dest: "abi.NamedTuple", a: Expr, b: Expr) -> Expr:
    """Set a 2-field (Bool, Bool) NamedTuple from raw TealType values."""
    av, bv = abi.Bool(), abi.Bool()
    return Seq(av.set(a), bv.set(b), dest.set(av, bv))


def set_bool_uint64(dest: "abi.NamedTuple", a: Expr, b: Expr) -> Expr:
    """Set a 2-field (Bool, Uint64) NamedTuple from raw TealType values."""
    av, bv = abi.Bool(), abi.Uint64()
    return Seq(av.set(a), bv.set(b), dest.set(av, bv))


def box_key(prefix: str, *parts: Expr) -> Expr:
    """2-byte ASCII prefix + sha256(parts joined by '|')."""
    assert len(prefix) == 2
    joined = parts[0]
    for p in parts[1:]:
        joined = Concat(joined, Bytes("|"), p)
    return Concat(Bytes(prefix), Sha256(joined))


# ---------------------------------------------------------------------------
# ARC-4 return types
# ---------------------------------------------------------------------------

class CountReturn(abi.NamedTuple):
    l1_count: abi.Field[abi.Uint64]
    l2_count: abi.Field[abi.Uint64]
    count_match: abi.Field[abi.Bool]


class RescindReturn(abi.NamedTuple):
    rescinded: abi.Field[abi.Bool]
    count_match: abi.Field[abi.Bool]


class ReplaceReturn(abi.NamedTuple):
    replaced: abi.Field[abi.Bool]
    count_match: abi.Field[abi.Bool]


class PeriodCloseReturn(abi.NamedTuple):
    committed: abi.Field[abi.Bool]
    timestamp: abi.Field[abi.Uint64]


# ---------------------------------------------------------------------------
# Router / bare app-call handling
#
# Update and delete are permanently disabled: the enforcement logic below
# is the whole point of putting this on-chain, so it must not be
# alterable after deployment. opt_in / close_out are not meaningful for
# this app (no per-account local state is used) so they are rejected too.
# ---------------------------------------------------------------------------

router = Router(
    "ShywareTwoList",
    BareCallActions(
        no_op=OnCompleteAction.create_only(Approve()),
        opt_in=OnCompleteAction.never(),
        close_out=OnCompleteAction.never(),
        update_application=OnCompleteAction.never(),
        delete_application=OnCompleteAction.never(),
    ),
    clear_state=Approve(),
)


# ---------------------------------------------------------------------------
# 1) submit_two_list_write
# ---------------------------------------------------------------------------

@router.method
def submit_two_list_write(
    scoping_id: abi.String,
    submission_id: abi.String,
    payload_commitment: abi.String,
    identity_hash: abi.String,
    *,
    output: CountReturn,
) -> Expr:
    l1_key = ScratchVar(TealType.bytes)
    l2_key = ScratchVar(TealType.bytes)
    cnt_key = ScratchVar(TealType.bytes)
    new_count = ScratchVar(TealType.uint64)
    cnt_val = App.box_get(cnt_key.load())

    return Seq(
        # required fields -- reject if either list is missing its field
        Assert(Len(scoping_id.get()) > Int(0)),
        Assert(Len(submission_id.get()) > Int(0)),
        Assert(Len(payload_commitment.get()) > Int(0)),
        Assert(Len(identity_hash.get()) > Int(0)),

        # (1) REJECTION PREDICATE -- no join key between L1 and L2 is ever
        # written. sha256(submissionId) must not equal identityHash.
        Assert(Sha256(submission_id.get()) != identity_hash.get()),

        l1_key.store(box_key("L1", scoping_id.get(), submission_id.get())),
        l2_key.store(box_key("L2", scoping_id.get(), identity_hash.get())),
        cnt_key.store(box_key("CN", scoping_id.get())),

        # (2) SYBIL RESISTANCE -- one identity, one submission, per
        # scoping id. box_create returns 0 if the box already exists;
        # Assert on that return value rejects the whole transaction.
        Assert(App.box_create(l2_key.load(), Int(1))),
        App.box_replace(l2_key.load(), Int(0), Bytes("base16", "0x01")),

        # (3) REPLAY PROTECTION -- submissionId not already used under
        # this scopingId. Same box_create-return-value pattern.
        Assert(App.box_create(l1_key.load(), Len(payload_commitment.get()))),
        App.box_replace(l1_key.load(), Int(0), payload_commitment.get()),

        # (4) on success: write L1, write L2 (above), increment the
        # per-scopingId counter, report count-match.
        cnt_val,
        new_count.store(
            If(cnt_val.hasValue(), Btoi(cnt_val.value()), Int(0)) + Int(1)
        ),
        App.box_put(cnt_key.load(), Itob(new_count.load())),

        set_uint64_bool(output, new_count.load(), new_count.load(), Int(1)),
    )


# ---------------------------------------------------------------------------
# 2) get_count -- read-only convenience method for on-chain composability.
# The JS adapter itself reads the "CN"+sha256(scopingId) box directly via
# algod's box-read endpoint and does not call this method (no transaction
# needed for a read), per LedgerInterface.getCount's contract.
# ---------------------------------------------------------------------------

@router.method
def get_count(scoping_id: abi.String, *, output: CountReturn) -> Expr:
    cnt_key = ScratchVar(TealType.bytes)
    cnt_val = App.box_get(cnt_key.load())
    count = ScratchVar(TealType.uint64)

    return Seq(
        cnt_key.store(box_key("CN", scoping_id.get())),
        cnt_val,
        count.store(If(cnt_val.hasValue(), Btoi(cnt_val.value()), Int(0))),
        set_uint64_bool(output, count.load(), count.load(), Int(1)),
    )


# ---------------------------------------------------------------------------
# 3) rescind_two_list_write -- delete both L1 and L2, decrement count.
# Both boxes must actually exist; box_delete's return value is asserted
# so a rescind of a submission that was never written (or already
# rescinded) fails cleanly instead of silently no-op'ing.
# ---------------------------------------------------------------------------

@router.method
def rescind_two_list_write(
    scoping_id: abi.String,
    submission_id: abi.String,
    identity_hash: abi.String,
    *,
    output: RescindReturn,
) -> Expr:
    l1_key = ScratchVar(TealType.bytes)
    l2_key = ScratchVar(TealType.bytes)
    cnt_key = ScratchVar(TealType.bytes)
    cnt_val = App.box_get(cnt_key.load())
    new_count = ScratchVar(TealType.uint64)

    return Seq(
        l1_key.store(box_key("L1", scoping_id.get(), submission_id.get())),
        l2_key.store(box_key("L2", scoping_id.get(), identity_hash.get())),
        cnt_key.store(box_key("CN", scoping_id.get())),

        Assert(App.box_delete(l1_key.load())),
        Assert(App.box_delete(l2_key.load())),

        cnt_val,
        Assert(cnt_val.hasValue()),
        new_count.store(Btoi(cnt_val.value()) - Int(1)),
        App.box_put(cnt_key.load(), Itob(new_count.load())),

        set_bool_bool(output, Int(1), Int(1)),
    )


# ---------------------------------------------------------------------------
# 4) replace_two_list_write -- delete old L1, write new L1 under the same
# rejection-predicate check as submit. L2 and the count are left
# untouched: this is a payload swap for an already-registered
# participant, not a new registration.
# ---------------------------------------------------------------------------

@router.method
def replace_two_list_write(
    scoping_id: abi.String,
    old_submission_id: abi.String,
    new_submission_id: abi.String,
    new_payload_commitment: abi.String,
    identity_hash: abi.String,
    *,
    output: ReplaceReturn,
) -> Expr:
    old_l1_key = ScratchVar(TealType.bytes)
    new_l1_key = ScratchVar(TealType.bytes)
    l2_key = ScratchVar(TealType.bytes)
    l2_len = App.box_length(l2_key.load())

    return Seq(
        Assert(Len(new_submission_id.get()) > Int(0)),
        Assert(Len(new_payload_commitment.get()) > Int(0)),

        # same rejection predicate as submit, checked against the *new*
        # submissionId
        Assert(Sha256(new_submission_id.get()) != identity_hash.get()),

        l2_key.store(box_key("L2", scoping_id.get(), identity_hash.get())),
        # caller must already be a registered participant for this
        # scopingId -- L2 is left untouched, only asserted present
        l2_len,
        Assert(l2_len.hasValue()),

        old_l1_key.store(box_key("L1", scoping_id.get(), old_submission_id.get())),
        new_l1_key.store(box_key("L1", scoping_id.get(), new_submission_id.get())),

        Assert(App.box_delete(old_l1_key.load())),
        Assert(App.box_create(new_l1_key.load(), Len(new_payload_commitment.get()))),
        App.box_replace(new_l1_key.load(), Int(0), new_payload_commitment.get()),

        set_bool_bool(output, Int(1), Int(1)),
    )


# ---------------------------------------------------------------------------
# 5) commit_period_close -- one-time-only per scopingId. box_create's
# own already-exists signal enforces "reject if already closed" with no
# extra state needed.
# ---------------------------------------------------------------------------

@router.method
def commit_period_close(
    scoping_id: abi.String,
    l1_merkle_root: abi.String,
    l2_merkle_root: abi.String,
    attestation: abi.String,
    *,
    output: PeriodCloseReturn,
) -> Expr:
    pc_key = ScratchVar(TealType.bytes)
    value = ScratchVar(TealType.bytes)
    timestamp = ScratchVar(TealType.uint64)

    return Seq(
        Assert(Len(l1_merkle_root.get()) == Int(32)),
        Assert(Len(l2_merkle_root.get()) == Int(32)),
        Assert(Len(attestation.get()) > Int(0)),

        pc_key.store(box_key("PC", scoping_id.get())),
        value.store(Concat(l1_merkle_root.get(), l2_merkle_root.get(), attestation.get())),
        timestamp.store(Global.latest_timestamp()),

        # reject if already closed
        Assert(App.box_create(pc_key.load(), Len(value.load()))),
        App.box_replace(pc_key.load(), Int(0), value.load()),

        set_bool_uint64(output, Int(1), timestamp.load()),
    )


# ---------------------------------------------------------------------------
# Compile
# ---------------------------------------------------------------------------

def compile_contract():
    approval_ast, clear_ast, contract = router.compile_program(
        version=8,
        optimize=OptimizeOptions(scratch_slots=True),
    )

    here = os.path.dirname(os.path.abspath(__file__))

    with open(os.path.join(here, "shyware_two_list_approval.teal"), "w") as f:
        f.write(approval_ast)

    with open(os.path.join(here, "shyware_two_list_clear.teal"), "w") as f:
        f.write(clear_ast)

    with open(os.path.join(here, "shyware_two_list.arc4.json"), "w") as f:
        f.write(json.dumps(contract.dictify(), indent=2))

    return approval_ast, clear_ast, contract


if __name__ == "__main__":
    compile_contract()
    print("Compiled shyware_two_list_approval.teal, shyware_two_list_clear.teal, "
          "shyware_two_list.arc4.json")
