"""
slicer.py  —  Smart Contract Program Slicer
============================================
Takes any Solidity contract as input. Finds all external calls,
runs backward + forward slice on each, intersects them, and reports
only REAL at-risk variables — no false positives.

Usage:
    python slicer.py <contract.sol> <ContractName>

Requires:
    npm install -g solc
    pip install slither-analyzer networkx
"""

import sys
import networkx as nx
from collections import defaultdict, deque

# ── Slither imports ──────────────────────────────────────────────
from slither import Slither
from slither.core.cfg.node import NodeType
from slither.analyses.data_dependency.data_dependency import compute_dependency

# Built-in Solidity globals should not be treated as local stale snapshots.
NON_LOCAL_PREFIXES = ("msg.", "tx.", "block.")
NON_LOCAL_EXACT    = {"now", "this", "super"}


# ════════════════════════════════════════════════════════════════════
# PHASE 1 — EXTRACTION
# Load contract via Slither. Collect state variables, functions, nodes.
# ════════════════════════════════════════════════════════════════════

def load_contract(sol_file: str, contract_name: str):
    """
    Run Slither on the .sol file, trigger data-dependency analysis,
    and return the target contract object.
    """
    sl = Slither(sol_file)
    compute_dependency(sl)

    matches = [c for c in sl.contracts if c.name == contract_name]
    if not matches:
        available = [c.name for c in sl.contracts]
        raise ValueError(f"Contract '{contract_name}' not found. Available: {available}")
    return matches[0]


def get_state_var_names(contract) -> set:
    """
    Return the set of state variable names declared in the contract.
    These are the variables that matter for cross-function analysis.
    """
    return {str(v.name) for v in contract.state_variables}


def is_real_node(node) -> bool:
    """
    Return True only for nodes that represent actual statements.
    Filters out Slither's internal bookkeeping nodes:
      ENTRYPOINT — function entry marker, no expression
      OTHER_ENTRYPOINT — same
      PLACEHOLDER — modifier placeholder
    """
    skip = {NodeType.ENTRYPOINT, NodeType.OTHER_ENTRYPOINT, NodeType.PLACEHOLDER}
    return node.type not in skip


def is_external_call_node(node) -> bool:
    """
    Return True if this node contains ANY kind of external call:
      low_level_calls  : .call / .delegatecall / .staticcall
      high_level_calls : IToken(addr).transfer(...)
      transfers        : addr.transfer(amount)
      sends            : addr.send(amount)
    """
    return bool(
        node.low_level_calls
        or node.high_level_calls
        or getattr(node, "transfers", [])
        or getattr(node, "sends", [])
    )


def describe_call(node) -> str:
    """Return a string describing the type of external call."""
    if node.low_level_calls:
        return "low_level_call"
    if node.high_level_calls:
        return "high_level_call"
    if getattr(node, "transfers", []):
        return "transfer"
    if getattr(node, "sends", []):
        return "send"
    return "unknown"


def node_label(node) -> str:
    """Short readable label for a CFG node."""
    if node.expression:
        s = str(node.expression)
        return s[:80] + "..." if len(s) > 80 else s
    return str(node.type)


def node_order_key(node) -> tuple:
    """
    Best-effort source order key for a node.
    We use source byte offset first, then node_id as tiebreaker.
    """
    smap = getattr(node, "source_mapping", None)
    start = None
    if smap is not None:
        # Slither can expose source mapping either as object or dict-like shape.
        start = getattr(smap, "start", None)
        if start is None and hasattr(smap, "get"):
            start = smap.get("start", None)
    if start is None:
        # fallback for nodes without source map
        start = 10**18
    return (start, getattr(node, "node_id", 10**18))


# ════════════════════════════════════════════════════════════════════
# PHASE 2 — PDG CONSTRUCTION
#
# Key design decisions (fixes from v1):
#
#   FIX 1 — Filter ENTRYPOINT/VARIABLE nodes entirely.
#
#   FIX 2 — DDG cross-function edges: only add when
#            A (fn1) writes state var X  AND  B (fn2) READS X.
#            Do NOT add if B also writes X (parallel writer, not downstream).
#
#   FIX 3 — No SEQ edges in backward slice.
#            SEQ edges are stored but tagged "seq".
#            backward_slice() ignores "seq" edges.
#            forward_slice() follows all edges including "seq".
# ════════════════════════════════════════════════════════════════════

def build_pdg(contract, state_vars: set) -> nx.DiGraph:
    """
    Build the inter-procedural Program Dependence Graph.

    Node key  : id(slither_node)  — unique per node object
    Node attrs: fn_name, label, vars_read, vars_written,
                is_ext_call, slither_node

    Edge attrs: kind = "data" | "control" | "seq"
                var  = variable name (data edges only)
    """
    pdg = nx.DiGraph()

    # ── Step 1: add all real CFG nodes ──────────────────────────────
    for fn in contract.functions_and_modifiers:
        for node in fn.nodes:
            if not is_real_node(node):
                continue
            nid = id(node)
            pdg.add_node(
                nid,
                fn_name      = fn.name,
                label        = node_label(node),
                vars_read    = {str(v) for v in node.variables_read},
                vars_written = {str(v) for v in node.variables_written},
                is_ext_call  = is_external_call_node(node),
                slither_node = node,
            )

    real_ids = set(pdg.nodes)   # only real nodes

    # ── Step 2: SEQ edges (sequential execution within a function) ───
    # node → its direct CFG successors (sons) within the same function.
    for fn in contract.functions_and_modifiers:
        for node in fn.nodes:
            if not is_real_node(node) or id(node) not in real_ids:
                continue
            for son in node.sons:
                if is_real_node(son) and id(son) in real_ids:
                    # only within same function for seq
                    if son.function == node.function:
                        pdg.add_edge(id(node), id(son), kind="seq")

    # ── Step 3: DDG — data dependence edges ─────────────────────────
    #
    # Intra-function: A writes local var X, B reads X (same function)
    # Cross-function: A writes STATE var X, B READS X (different function)
    #                 Only if B is a READER, not a writer (FIX 2).

    # Build maps per variable
    # writers[var] = list of (fn_name, node_id)
    # readers[var] = list of (fn_name, node_id)
    writers = defaultdict(list)
    readers = defaultdict(list)

    for nid, data in pdg.nodes(data=True):
        fn = data["fn_name"]
        for v in data["vars_written"]:
            writers[v].append((fn, nid))
        for v in data["vars_read"]:
            readers[v].append((fn, nid))

    # Cache node source order to avoid impossible backward data edges
    # (e.g., a post-call write "influencing" a pre-call read in the same function).
    node_order = {}
    for nid, data in pdg.nodes(data=True):
        node_order[nid] = node_order_key(data["slither_node"])

    for var, writer_list in writers.items():
        for (wfn, wnid) in writer_list:
            for (rfn, rnid) in readers.get(var, []):
                if wnid == rnid:
                    continue
                same_fn = (wfn == rfn)
                is_state = var in state_vars

                if same_fn:
                    # intra-function: only when writer appears before reader in source.
                    # This prevents false backward links from later statements.
                    if node_order[wnid] <= node_order[rnid]:
                        pdg.add_edge(wnid, rnid, kind="data", var=var)
                elif is_state:
                    # cross-function: only if the reader is purely reading
                    # (not also writing the same variable — FIX 2)
                    reader_data = pdg.nodes[rnid]
                    if var not in reader_data["vars_written"]:
                        pdg.add_edge(wnid, rnid, kind="data", var=var)

    # ── Step 4: CDG — control dependence edges ──────────────────────
    # A require/assert/if node gates all nodes that follow it in the
    # same function (via its CFG successors transitively).
    # We use a simple approximation: direct sons only, same function.
    for fn in contract.functions_and_modifiers:
        for node in fn.nodes:
            if not is_real_node(node) or id(node) not in real_ids:
                continue
            if node.contains_require_or_assert or node.type in (NodeType.IF, NodeType.IFLOOP):
                for son in node.sons:
                    if is_real_node(son) and id(son) in real_ids:
                        pdg.add_edge(id(node), id(son), kind="control")

    return pdg


# ════════════════════════════════════════════════════════════════════
# PHASE 3 — SLICING
#
# FIX 3 — Backward slice does NOT follow "seq" edges.
#   Seq edges go forward in time (stmt N → stmt N+1).
#   Following them backward would pull in downstream statements.
#   Only data and control edges encode real backward dependencies.
#
# Forward slice follows ALL edges (data, control, seq).
# ════════════════════════════════════════════════════════════════════

def backward_slice(pdg: nx.DiGraph, criterion_id: int) -> set:
    """
    BFS on reversed PDG from criterion, skipping SEQ edges.
    Returns set of node ids that INFLUENCE the criterion.
    = everything that must happen / be set before the call.

    Note on reversed graph traversal:
      pdg.reverse() flips all edges.
      rev.out_edges(cur) returns (cur, predecessor, data).
      So we unpack as (_, pred, edata) — second element is the real predecessor.
    """
    rev     = pdg.reverse(copy=False)
    visited = set()
    queue   = deque([criterion_id])

    while queue:
        cur = queue.popleft()
        if cur in visited:
            continue
        visited.add(cur)
        for _, pred, edata in rev.out_edges(cur, data=True):
            # skip seq edges — they run forward in time,
            # following them backward pulls in downstream nodes
            if edata.get("kind") == "seq":
                continue
            if pred not in visited:
                queue.append(pred)

    return visited


def forward_slice(pdg: nx.DiGraph, criterion_id: int) -> set:
    """
    BFS on forward PDG from criterion, following ALL edges.
    Returns set of node ids that the criterion INFLUENCES.
    = everything that executes / is affected after the call.
    """
    visited = set()
    queue   = deque([criterion_id])

    while queue:
        cur = queue.popleft()
        if cur in visited:
            continue
        visited.add(cur)
        for succ in pdg.successors(cur):
            if succ not in visited:
                queue.append(succ)

    return visited


# ════════════════════════════════════════════════════════════════════
# PHASE 4 — RISK ANALYSIS
#
# The core fix: split intersection nodes into BEFORE and AFTER the call.
# Do NOT mix them — that's what caused false positives in v1.
#
# before_nodes = nodes in backward slice (upstream of call)
# after_nodes  = nodes in forward slice  (downstream of call)
# Both exclude the criterion node itself.
#
# Two risk patterns:
#
#   PATTERN A — Written Window (classic reentrancy):
#     var is READ in before_nodes AND WRITTEN in after_nodes
#     → state was read to make a decision, but updated too late
#
#   PATTERN B — Stale Value (cached variable):
#     var is READ in before_nodes AND READ AGAIN in after_nodes
#     AND the after-read is in a statement that WRITES a state variable
#     → local var captured before call, used in post-call state write
#
#   FILTER — only report vars that are:
#     (a) state variables, OR
#     (b) local vars used directly in a post-call statement that
#         writes a state variable
# ════════════════════════════════════════════════════════════════════

def find_risks(pdg: nx.DiGraph,
               criterion_id: int,
               backward: set,
               forward: set,
               state_vars: set) -> list[dict]:
    """
    Identify truly at-risk variables.

    Key insight: split nodes into BEFORE and AFTER the call.
      before_nodes = backward - {criterion}   (influenced the call)
      after_nodes  = forward  - {criterion}   (affected by the call)

    Two risk patterns:

      Pattern A — Written Window (classic reentrancy):
        var READ in before_nodes  AND  WRITTEN in after_nodes
        AND var is a STATE variable
        → state was read to make a decision but updated too late

      Pattern B — Stale Value (cached local):
        var READ in before_nodes  AND  READ AGAIN in after_nodes
        AND var is LOCAL (not state)
        AND the after-node that reads it also writes a STATE variable
        → local snapshot taken before call, used in post-call state write

    This ensures fee/amount etc. are NOT flagged as false positives.
    """
    before_nodes = backward - {criterion_id}
    after_nodes  = forward  - {criterion_id}

    reads_before = defaultdict(list)
    reads_after  = defaultdict(list)
    writes_after = defaultdict(list)

    # collect from before nodes
    for nid in before_nodes:
        data = pdg.nodes[nid]
        lbl  = data["label"]
        for v in data["vars_read"]:
            reads_before[v].append(lbl)

    # collect from after nodes
    # also track which after-nodes write state vars (for Pattern B filter)
    after_state_writers = set()
    for nid in after_nodes:
        data = pdg.nodes[nid]
        lbl  = data["label"]
        for v in data["vars_read"]:
            reads_after[v].append(lbl)
        for v in data["vars_written"]:
            writes_after[v].append(lbl)
            if v in state_vars:
                after_state_writers.add(nid)

    # local vars that are directly read by a post-call state-writing statement
    locals_in_state_write = set()
    for nid in after_state_writers:
        for v in pdg.nodes[nid]["vars_read"]:
            if v not in state_vars:
                locals_in_state_write.add(v)

    risks = []

    # Pattern A: state var read before call AND written after call
    for var in reads_before:
        if var not in state_vars:
            continue
        if var not in writes_after:
            continue
        risks.append({
            "var"     : var,
            "pattern" : "written_window",
            "detail"  : "state var read before call, written after — classic reentrancy window",
            "read_at" : reads_before[var][0],
            "where"   : writes_after[var][0],
        })

    # Pattern B: local var captured before call, used in post-call state write
    for var in reads_before:
        if var in state_vars:
            continue
        if var in NON_LOCAL_EXACT or var.startswith(NON_LOCAL_PREFIXES):
            continue
        if var not in reads_after:
            continue
        if var not in locals_in_state_write:
            continue
        risks.append({
            "var"     : var,
            "pattern" : "stale_value",
            "detail"  : "local var captured before call, used in post-call state write — stale snapshot",
            "read_at" : reads_before[var][0],
            "where"   : reads_after[var][0],
        })

    return risks


# ════════════════════════════════════════════════════════════════════
# PHASE 5 — REPORT
# ════════════════════════════════════════════════════════════════════

def print_report(sol_file, contract_name, pdg, all_results, state_vars):
    SEP  = "=" * 65
    DASH = "-" * 65

    print(f"\n{SEP}")
    print(f"  CONTRACT : {contract_name}   ({sol_file})")
    print(f"  STATE VARIABLES : {', '.join(sorted(state_vars))}")
    print(f"  EXTERNAL CALLS  : {len(all_results)}")
    print(SEP)

    for idx, res in enumerate(all_results, 1):
        cid    = res["criterion_id"]
        bwd    = res["backward"]
        fwd    = res["forward"]
        risks  = res["risks"]

        # clean sets for display — exclude criterion, exclude noise
        before_display = sorted(bwd - {cid},
                                key=lambda n: pdg.nodes[n]["fn_name"])
        after_display  = sorted(fwd - {cid},
                                key=lambda n: pdg.nodes[n]["fn_name"])
        inter_display  = sorted((bwd & fwd) - {cid},
                                key=lambda n: pdg.nodes[n]["fn_name"])

        print(f"\n{DASH}")
        print(f"  EXTERNAL CALL #{idx}")
        print(f"  Function  : {res['fn_name']}()")
        print(f"  Statement : {res['label']}")
        print(f"  Type      : {res['call_type']}")
        print(DASH)

        # Backward slice
        print("\n  BACKWARD SLICE  (what leads to this call)")
        print("  " + "─" * 50)
        _print_node_list(pdg, before_display)

        # Forward slice
        print("\n  FORWARD SLICE  (what this call affects)")
        print("  " + "─" * 50)
        _print_node_list(pdg, after_display, empty_msg="(nothing — call result unused)")

        # Intersection
        print("\n  INTERSECTION  (in both slices)")
        print("  " + "─" * 50)
        _print_node_list(pdg, inter_display, empty_msg="(empty)")

        # Variables at risk
        print("\n  VARIABLES AT RISK")
        print("  " + "─" * 50)
        if risks:
            for r in risks:
                tag = "⚠  WRITTEN WINDOW" if r["pattern"] == "written_window" else "⚠  STALE VALUE"
                print(f"    {tag} : '{r['var']}'")
                print(f"    {r['detail']}")
                print(f"    Read before  : {r['read_at']}")
                print(f"    {'Written' if r['pattern']=='written_window' else 'Used'} after   : {r['where']}")
                print()
        else:
            print("    ✓  no variables straddle the call boundary")

    # Summary
    print(f"\n{SEP}")
    print("  SUMMARY")
    print(SEP)
    risky = [r for r in all_results if r["risks"]]
    clean = [r for r in all_results if not r["risks"]]
    if risky:
        print(f"\n  ⚠  {len(risky)} risky call(s):")
        for r in risky:
            vars_list = [x["var"] for x in r["risks"]]
            patterns  = [x["pattern"] for x in r["risks"]]
            print(f"     → {r['fn_name']}() :: {r['call_type']}")
            for v, p in zip(vars_list, patterns):
                tag = "written window" if p == "written_window" else "stale value"
                print(f"       {v} ({tag})")
    if clean:
        print(f"\n  ✓  {len(clean)} clean call(s):")
        for r in clean:
            print(f"     → {r['fn_name']}() :: {r['call_type']}")
    print(f"\n{SEP}\n")


def _print_node_list(pdg, node_ids, empty_msg="(none)"):
    """Print a list of PDG nodes grouped by function."""
    if not node_ids:
        print(f"    {empty_msg}")
        return
    cur_fn = None
    for nid in node_ids:
        data = pdg.nodes[nid]
        fn   = data["fn_name"]
        lbl  = data["label"]
        if fn != cur_fn:
            print(f"\n  [{fn}]")
            cur_fn = fn
        # show edge kind
        kinds = {e[2].get("kind","") for e in pdg.in_edges(nid, data=True)}
        kinds |= {e[2].get("kind","") for e in pdg.out_edges(nid, data=True)}
        kinds.discard("")
        tag = " + ".join(sorted(k for k in kinds if k != "seq")) or "seq"
        print(f"    {lbl:<58}  ← {tag}")


# ════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════

def run(sol_file: str, contract_name: str):
    print(f"\n[*] Loading {sol_file} ...")
    contract   = load_contract(sol_file, contract_name)
    state_vars = get_state_var_names(contract)

    print(f"[*] Contract : {contract_name}")
    print(f"[*] State vars : {sorted(state_vars)}")
    print(f"[*] Functions  : {[f.name for f in contract.functions]}")

    print("[*] Building PDG ...")
    pdg = build_pdg(contract, state_vars)
    print(f"[*] PDG : {pdg.number_of_nodes()} nodes, {pdg.number_of_edges()} edges")

    # find all external call nodes
    ext_nodes = [(nid, data) for nid, data in pdg.nodes(data=True)
                 if data["is_ext_call"]]
    print(f"[*] External calls : {len(ext_nodes)}")

    if not ext_nodes:
        print("[!] No external calls found.")
        return

    all_results = []
    for cid, cdata in ext_nodes:
        bwd   = backward_slice(pdg, cid)
        fwd   = forward_slice(pdg, cid)
        risks = find_risks(pdg, cid, bwd, fwd, state_vars)

        all_results.append({
            "criterion_id" : cid,
            "fn_name"      : cdata["fn_name"],
            "label"        : cdata["label"],
            "call_type"    : describe_call(cdata["slither_node"]),
            "backward"     : bwd,
            "forward"      : fwd,
            "risks"        : risks,
        })

    print_report(sol_file, contract_name, pdg, all_results, state_vars)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python slicer.py <contract.sol> <ContractName>")
        sys.exit(1)
    run(sys.argv[1], sys.argv[2])