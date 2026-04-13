from slither.slither import Slither
import networkx as nx

# -----------------------------
# STEP 1: Load contract
# -----------------------------
slither = Slither("contract.sol")

contract = slither.contracts[0]
function = contract.functions[0]
nodes = function.nodes

print(f"\n[+] Analyzing function: {function.name}")

# -----------------------------
# STEP 2: Detect external call
# -----------------------------
def is_external_call(node):
    for ir in node.irs:
        if "call" in str(ir).lower():
            return True
    return False

call_node = None
for node in nodes:
    if is_external_call(node):
        call_node = node
        break

if not call_node:
    print("❌ No external call found")
    exit()

print("\n[+] External Call Node:")
print("  ", call_node)

# -----------------------------
# STEP 3: Split before/after
# -----------------------------
before_nodes = []
after_nodes = []

seen_call = False

for node in nodes:
    if node == call_node:
        seen_call = True
        continue

    if not seen_call:
        before_nodes.append(node)
    else:
        after_nodes.append(node)

# -----------------------------
# STEP 4: Build GRAPH
# Two kinds of edges:
#   1. Def-use: n1 writes a var that n2 reads (local data flow)
#   2. State-alias: n1 and n2 both touch the same STATE variable
#      (mapping/storage). This connects `balances[msg.sender] = 0`
#      back to `amount = balances[msg.sender]` through `balances`.
#      Gated to StateVariable only — avoids pulling in locals like `fee`.
# -----------------------------
from slither.core.variables.state_variable import StateVariable

G = nx.DiGraph()

for node in nodes:
    G.add_node(node)

# Edge type 1: pure def-use (local + state)
for n1 in nodes:
    for n2 in nodes:
        if n1 is n2:
            continue
        if set(n1.variables_written) & set(n2.variables_read):
            G.add_edge(n1, n2)

# Edge type 2: state-alias — both nodes touch the same StateVariable
# Direction: earlier node → later node (preserves program order)
node_list = list(nodes)
for i, n1 in enumerate(node_list):
    for j, n2 in enumerate(node_list):
        if i >= j:
            continue
        sv1 = {v for v in (set(n1.variables_read) | set(n1.variables_written))
               if isinstance(v, StateVariable)}
        sv2 = {v for v in (set(n2.variables_read) | set(n2.variables_written))
               if isinstance(v, StateVariable)}
        if sv1 & sv2:
            G.add_edge(n1, n2)
            G.add_edge(n2, n1)  # bidirectional so backward slice works

# -----------------------------
# STEP 5: SLICING FUNCTIONS
# -----------------------------
def forward_slice(G, start_nodes):
    visited = set(start_nodes)
    stack = list(start_nodes)

    while stack:
        node = stack.pop()
        for succ in G.successors(node):
            if succ not in visited:
                visited.add(succ)
                stack.append(succ)

    return visited


def backward_slice(G, start_nodes):
    visited = set(start_nodes)
    stack = list(start_nodes)

    while stack:
        node = stack.pop()
        for pred in G.predecessors(node):
            if pred not in visited:
                visited.add(pred)
                stack.append(pred)

    return visited

# -----------------------------
# STEP 6: Identify call's direct input variables only.
# We intentionally do NOT expand via backward_slice here —
# that was pulling `fee` in because it shares `amount` with the call.
# We only want variables the call node directly reads.
# -----------------------------
call_reads = set(call_node.variables_read)

print("\n[+] Direct Call Variables:")
for v in call_reads:
    print("  ", v)

# -----------------------------
# STEP 7: Filter relevant nodes
#
# read_nodes  — before the call, writes a var the call DIRECTLY reads
# write_nodes — after  the call, writes a var that was also read before
#               the call (i.e. a state variable like balances)
#
# Key change: filter read_nodes against call_reads (direct),
# not the expanded backward-slice vars. This removes `fee`
# because `fee` is not directly read by the call node.
# -----------------------------

# Variables written before the call that the call directly uses
pre_written = set()
for n in before_nodes:
    pre_written.update(n.variables_written)

read_nodes = [
    n for n in before_nodes
    if set(n.variables_written) & call_reads
]

# Variables that were defined before the call (state touched before)
pre_vars = set()
for n in before_nodes:
    pre_vars.update(n.variables_read)
    pre_vars.update(n.variables_written)

# After the call, writes something that was in scope before the call
write_nodes = [
    n for n in after_nodes
    if set(n.variables_written) & pre_vars
]

print("\n[+] Relevant Read Nodes (before call):")
for n in read_nodes:
    print("  ", n)

print("\n[+] Relevant Write Nodes (after call):")
for n in write_nodes:
    print("  ", n)

# -----------------------------
# STEP 8: Apply slicing
# Forward from read_nodes  → everything reachable downstream
# Backward from write_nodes → everything that feeds the write
# Chop = intersection: nodes on a path FROM read TO write
# Always include call_node in chop (it's the pivot)
# -----------------------------
fwd = forward_slice(G, read_nodes)
bwd = backward_slice(G, write_nodes)

chop = fwd & bwd
# Always include the anchor nodes — they're the reentrancy pattern endpoints
chop.add(call_node)
chop.update(read_nodes)
chop.update(write_nodes)

# -----------------------------
# STEP 9: Print results
# -----------------------------
print("\n[+] Forward Slice Nodes:")
for n in fwd:
    print("  ", n)

print("\n[+] Backward Slice Nodes:")
for n in bwd:
    print("  ", n)

print("\n[+] INTERSECTION (CHOP):")
for n in chop:
    print("  ", n)

# -----------------------------
# STEP 10: Extract variables
# Only report vars that are directly involved in the chop nodes,
# filtered to those that matter for reentrancy:
#   - read before the call
#   - written after the call
#   - or directly read by the call
# -----------------------------
danger_vars = set()

for node in chop:
    danger_vars.update([str(v) for v in node.variables_read])
    danger_vars.update([str(v) for v in node.variables_written])

# Remove pure local temporaries (success, fee) that are not
# state variables and not directly read by the call
call_read_names = {str(v) for v in call_node.variables_read}
state_var_names = set()
for node in chop:
    for v in list(node.variables_read) + list(node.variables_written):
        if isinstance(v, StateVariable):
            state_var_names.add(str(v))

danger_vars = danger_vars & (call_read_names | state_var_names)

print("\n[🔥] Dangerous Variables (FINAL):")
for v in sorted(danger_vars):
    print("  ", v)