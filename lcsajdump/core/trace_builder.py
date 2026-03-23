"""
trace_builder.py — Build an animation trace for the 3D visualizer.

The trace is a list of events consumed by animationEngine.js to replay:
  Phase 1 — graph decomposition: nodes appear, then edges
  Phase 2 — tail seeding: each tool lights its tail nodes; exclusive tails get a marker
  Phase 3 — BFS walk: top gadgets replay backward BFS path step by step
  Phase 4 — final coverage: nodes colored by tool coverage

Event schema (all events share a 'tick' int and 'type' str):

  { type: "phase_start",   tick, phase: int, label: str }
  { type: "node_appear",   tick, id: str }
  { type: "phase1_bulk",   tick }                          # all nodes at once (> 2000)
  { type: "edge_appear",   tick, source: str, target: str }
  { type: "tail_light",    tick, id: str, tool: str }      # tool ∈ {lcsaj, ropper, ropgadget}
  { type: "tail_exclusive", tick, id: str, tool: str }     # tail found ONLY by this tool
  { type: "bfs_step",      tick, gadget_id: int, node_id: str, depth: int }
  { type: "coverage_final", tick }                         # signal to apply final colors
"""

_PHASE_LABELS = {
    1: "Phase 1 — Graph Decomposition",
    2: "Phase 2 — Tail Seeding",
    3: "Phase 3 — BFS Replay",
    4: "Phase 4 — Coverage Comparison",
}

_BULK_THRESHOLD = 2000  # nodes above this use phase1_bulk instead of per-node events


def build_animation_trace(graph_manager, finder, coverage, top_n: int = 30):
    """
    Build the animation trace list and a phase_map dict.

    Args:
        graph_manager : LCSAJGraph — .nodes, .addr_to_node, .reverse_graph
        finder        : RainbowFinder — .grouped_gadgets
        coverage      : dict returned by compute_tool_coverage()
        top_n         : max gadgets to animate in Phase 3

    Returns:
        (trace, phase_map)
        trace     : list[dict] — events in tick order
        phase_map : dict[int, int] — phase number → first tick of that phase
    """
    trace = []
    tick = 0
    phase_map = {}

    addr_to_node = graph_manager.addr_to_node
    nodes_sorted = sorted(graph_manager.nodes, key=lambda n: n["start"])

    tail_sets     = coverage.get("tail_sets", {})
    lcsaj_tails   = tail_sets.get("lcsaj",     set())
    ropper_tails  = tail_sets.get("ropper",    set())
    rg_tails      = tail_sets.get("ropgadget", set())

    # ── Phase 1: graph decomposition ─────────────────────────────────────────
    phase_map[1] = tick
    trace.append({"type": "phase_start", "tick": tick, "phase": 1,
                  "label": _PHASE_LABELS[1]})
    tick += 1

    if len(nodes_sorted) > _BULK_THRESHOLD:
        # Emit a single bulk event — visualizer shows all nodes instantly
        trace.append({"type": "phase1_bulk", "tick": tick})
        tick += 1
    else:
        for node in nodes_sorted:
            trace.append({"type": "node_appear", "tick": tick, "id": hex(node["start"])})
            tick += 1

    # Edges (emitted after all nodes so links don't dangle)
    seen_edges = set()
    for target_addr, predecessors in graph_manager.reverse_graph.items():
        if target_addr not in addr_to_node:
            continue
        for pred_addr in predecessors:
            if pred_addr not in addr_to_node:
                continue
            key = (pred_addr, target_addr)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            trace.append({
                "type":   "edge_appear",
                "tick":   tick,
                "source": hex(pred_addr),
                "target": hex(target_addr),
            })
            tick += 1

    # ── Phase 2: tail seeding ────────────────────────────────────────────────
    phase_map[2] = tick
    trace.append({"type": "phase_start", "tick": tick, "phase": 2,
                  "label": _PHASE_LABELS[2]})
    tick += 1

    # Collect all tail addresses across tools
    all_tails = lcsaj_tails | ropper_tails | rg_tails
    for addr in sorted(all_tails):
        if addr not in addr_to_node:
            continue
        node_id = hex(addr)

        rpplus_tails = tail_sets.get("rp_plus", set())

        # Emit tail_light for each tool that seeds this node
        for tool, tset in (("lcsaj", lcsaj_tails),
                           ("ropper", ropper_tails),
                           ("ropgadget", rg_tails),
                           ("rp_plus", rpplus_tails)):
            if addr in tset:
                trace.append({"type": "tail_light", "tick": tick,
                               "id": node_id, "tool": tool})
                tick += 1

        # Emit tail_exclusive when lcsajdump is the ONLY tool seeding this node
        if addr in lcsaj_tails and addr not in ropper_tails and addr not in rg_tails \
                and addr not in rpplus_tails:
            trace.append({"type": "tail_exclusive", "tick": tick,
                           "id": node_id, "tool": "lcsaj"})
            tick += 1

    # ── Phase 3: BFS replay ──────────────────────────────────────────────────
    phase_map[3] = tick
    trace.append({"type": "phase_start", "tick": tick, "phase": 3,
                  "label": _PHASE_LABELS[3]})
    tick += 1

    grouped = getattr(finder, "grouped_gadgets", {})
    # Sort by score descending; take top_n
    scored = []
    for sig, data in grouped.items():
        path = data["path"]
        score = finder.score_gadget(path)
        scored.append((score, sig, data))
    scored.sort(key=lambda x: x[0], reverse=True)

    for gadget_idx, (score, sig, data) in enumerate(scored[:top_n]):
        path = data["path"]          # list of block addresses, tail-last
        # Replay path from head to tail (depth 0 = first block, depth n-1 = tail)
        for depth, addr in enumerate(path):
            if addr not in addr_to_node:
                continue
            trace.append({
                "type":      "bfs_step",
                "tick":      tick,
                "gadget_id": gadget_idx,
                "node_id":   hex(addr),
                "depth":     depth,
            })
            tick += 1

    # ── Phase 4: final coverage ──────────────────────────────────────────────
    phase_map[4] = tick
    trace.append({"type": "phase_start", "tick": tick, "phase": 4,
                  "label": _PHASE_LABELS[4]})
    tick += 1
    trace.append({"type": "coverage_final", "tick": tick})
    tick += 1

    return trace, phase_map
