import json
import os
from datetime import datetime, timezone
from .config import ARCH_PROFILES


def _reconstruct_gadget(tail_addr, addr_to_node, reverse_graph, max_insns=12):
    """
    Reconstruct a simple gadget path via greedy backward traversal from tail_addr.
    Returns (path, signature, insn_count) or None if tail is not in graph.
    """
    if tail_addr not in addr_to_node:
        return None
    tail_node = addr_to_node[tail_addr]
    path = [tail_addr]
    total_insns = len(tail_node['insns'])
    curr = tail_addr

    for _ in range(8):   # max 8 predecessor blocks
        preds = [p for p in reverse_graph.get(curr, []) if p in addr_to_node]
        if not preds:
            break
        added = False
        for pred in preds:
            pred_count = len(addr_to_node[pred]['insns'])
            if total_insns + pred_count <= max_insns:
                path.insert(0, pred)
                total_insns += pred_count
                curr = pred
                added = True
                break
        if not added:
            break

    all_insns = []
    for a in path:
        all_insns.extend(addr_to_node[a]['insns'])
    sig = '; '.join(f"{i.mnemonic} {i.op_str}" for i in all_insns)
    return path, sig, total_insns


def _classify_terminator(mnem, profile):
    """Return a terminator_type string for a given mnemonic and arch profile."""
    m = mnem.lower()
    if m in profile["ret_mnems"]:
        return "ret"
    if m in profile.get("call_mnems", set()):
        return "call"
    if m.startswith(profile["branch_prefixes"]):
        return "conditional"
    if m in profile["unconditional_jumps"]:
        return "jump"
    return "fallthrough"


def _section_name_for_addr(addr, loader):
    """Return the ELF section name that contains `addr`, or '.text' as fallback."""
    if not hasattr(loader, 'path'):
        return ".text"
    try:
        from elftools.elf.elffile import ELFFile
        with open(loader.path, 'rb') as fh:
            elf = ELFFile(fh)
            for section in elf.iter_sections():
                sh_addr = section['sh_addr']
                sh_size = section['sh_size']
                if sh_addr <= addr < sh_addr + sh_size:
                    return section.name
    except Exception:
        pass
    return ".text"


def export_graph_json(binary_path, arch, loader, graph_manager, finder, output_path,
                      coverage=None, trace=None, phase_map=None):
    """
    Serialize the full LCSAJ graph (nodes + edges) and found gadgets to a JSON
    file suitable for consumption by the 3d-force-graph web visualizer.

    When `coverage` is provided, each node is annotated with:
        tool_coverage : {lcsaj, ropper, ropgadget} → bool
        is_tail       : {lcsaj, ropper, ropgadget} → bool

    When `trace` is provided, the output includes:
        animation_trace : list[event]
        phase_map       : {phase_int: first_tick}

    Args:
        binary_path  : path to the analyzed ELF binary
        arch         : architecture string ('x86_64', 'arm64', 'riscv64')
        loader       : BinaryLoader instance — used to resolve section names
        graph_manager: LCSAJGraph instance — .nodes, .addr_to_node, .reverse_graph
        finder       : RainbowFinder instance — .grouped_gadgets, score_gadget(), _classify_gadget()
        output_path  : destination .json file path
        coverage     : optional dict from compute_tool_coverage()
        trace        : optional list from build_animation_trace()
        phase_map    : optional dict from build_animation_trace()
    """
    profile = ARCH_PROFILES[arch]
    gm = graph_manager

    # ------------------------------------------------------------------
    # Build a fast addr→section-name lookup from loader.sections
    # loader.sections is a list of (base_addr, code_bytes) tuples
    # ------------------------------------------------------------------
    section_ranges = []
    if hasattr(loader, 'sections') and loader.sections:
        # Resolve section names from ELF if possible
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.constants import SH_FLAGS
            with open(loader.path, 'rb') as fh:
                elf = ELFFile(fh)
                for section in elf.iter_sections():
                    if section['sh_flags'] & SH_FLAGS.SHF_EXECINSTR:
                        section_ranges.append((
                            section['sh_addr'],
                            section['sh_addr'] + section['sh_size'],
                            section.name
                        ))
        except Exception:
            # Fallback: use numeric section indices from loader.sections
            for i, (base, data) in enumerate(loader.sections):
                name = ".text" if i == 0 else f".exec{i}"
                section_ranges.append((base, base + len(data), name))

    def addr_to_section(addr):
        for lo, hi, name in section_ranges:
            if lo <= addr < hi:
                return name
        return ".text"

    # ------------------------------------------------------------------
    # 1. Build node map  (hex_id → serializable dict)
    # ------------------------------------------------------------------
    node_map = {}

    # Strip full instruction arrays for large graphs to keep JSON size manageable.
    # infoPanel.js handles the missing array gracefully.
    _strip_insns = len(gm.nodes) > 1000

    for raw in gm.nodes:
        hex_id = hex(raw["start"])
        t_mnem = raw["last_insn"].mnemonic
        t_type = _classify_terminator(t_mnem, profile)

        node_entry = {
            "id":              hex_id,
            "start":           raw["start"],
            "end":             raw["end"],
            "insn_count":      len(raw["insns"]),
            "terminator":      t_mnem,
            "terminator_type": t_type,
            "section":         addr_to_section(raw["start"]),
            "gadget_ids":      [],
            "in_degree":       0,
            "out_degree":      0,
        }
        if not _strip_insns:
            node_entry["instructions"] = [
                {
                    "addr":     hex(i.address),
                    "mnemonic": i.mnemonic,
                    "operands": i.op_str,
                    "size":     i.size,
                }
                for i in raw["insns"]
            ]
        node_map[hex_id] = node_entry
        # Preserve direct_call_target metadata if present (lcsaj_direct challenge)
        if "direct_call_target" in raw:
            node_map[hex_id]["direct_call_target"] = hex(raw["direct_call_target"])

    # ------------------------------------------------------------------
    # 1b. Annotate nodes with multi-tool coverage (optional)
    # ------------------------------------------------------------------
    if coverage is not None:
        tail_sets        = coverage["tail_sets"]
        gadget_node_sets = coverage["gadget_node_sets"]
        simulated        = coverage.get("simulated", [])

        for raw in gm.nodes:
            hex_id = hex(raw["start"])
            addr   = raw["start"]
            if hex_id not in node_map:
                continue
            node_map[hex_id]["tool_coverage"] = {
                "lcsaj":     addr in gadget_node_sets.get("lcsaj",     set()),
                "ropper":    addr in gadget_node_sets.get("ropper",    set()),
                "ropgadget": addr in gadget_node_sets.get("ropgadget", set()),
                "rp_plus":   addr in gadget_node_sets.get("rp_plus",   set()),
            }
            node_map[hex_id]["is_tail"] = {
                "lcsaj":     addr in tail_sets.get("lcsaj",     set()),
                "ropper":    addr in tail_sets.get("ropper",    set()),
                "ropgadget": addr in tail_sets.get("ropgadget", set()),
                "rp_plus":   addr in tail_sets.get("rp_plus",   set()),
            }
            node_map[hex_id]["tail_simulated"] = {
                tool: tool in simulated
                for tool in ("ropper", "ropgadget", "rp_plus")
            }

    # ------------------------------------------------------------------
    # 2. Build edge list from reverse_graph (target → [predecessors])
    # ------------------------------------------------------------------
    links = []
    seen_edges = set()
    addr_to_node = gm.addr_to_node

    for target_addr, predecessors in gm.reverse_graph.items():
        if target_addr not in addr_to_node:
            continue
        target_hex = hex(target_addr)

        for pred_addr in predecessors:
            if pred_addr not in addr_to_node:
                continue
            pred_hex = hex(pred_addr)

            edge_key = (pred_hex, target_hex)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)

            pred_node = addr_to_node[pred_addr]
            last = pred_node["last_insn"]

            # Fallthrough: next sequential byte is the target block start
            if last.address + last.size == target_addr:
                e_type = "fallthrough"
            else:
                e_type = _classify_terminator(last.mnemonic, profile)

            links.append({"source": pred_hex, "target": target_hex, "type": e_type})

            if pred_hex in node_map:
                node_map[pred_hex]["out_degree"] += 1
            if target_hex in node_map:
                node_map[target_hex]["in_degree"] += 1

    # ------------------------------------------------------------------
    # 3. Build gadget list and back-fill gadget_ids on nodes
    # ------------------------------------------------------------------
    gadgets = []
    grouped = getattr(finder, "grouped_gadgets", {})

    for gidx, (sig, data) in enumerate(grouped.items()):
        path = data["path"]
        addrs_set = data["addresses"]

        score = finder.score_gadget(path)
        tag, category = finder._classify_gadget(path)

        total_insns = sum(
            len(addr_to_node[a]["insns"])
            for a in path
            if a in addr_to_node
        )

        for a in path:
            h = hex(a)
            if h in node_map:
                node_map[h]["gadget_ids"].append(gidx)

        # Determine which tools can also find this gadget (tail in their seed set)
        # and whether it is exclusive to lcsajdump
        exclusive_to = None
        if coverage is not None:
            tail_addr  = path[-1] if path else None
            other_tools = ("ropper", "ropgadget", "rp_plus")
            if tail_addr is not None:
                tail_sets_cov = coverage.get("tail_sets", {})
                other_have_tail = any(
                    tail_addr in tail_sets_cov.get(t, set())
                    for t in other_tools
                )
                if not other_have_tail and tail_addr in tail_sets_cov.get("lcsaj", set()):
                    exclusive_to = "lcsaj"

        entry = {
            "id":         gidx,
            "signature":  sig,
            "path":       [hex(a) for a in path],
            "score":      score,
            "tag":        tag,
            "category":   category,
            "duplicates": sorted([hex(a) for a in addrs_set]),
            "insn_count": total_insns,
        }
        if exclusive_to is not None:
            entry["exclusive_to"] = exclusive_to
        gadgets.append(entry)

    # ------------------------------------------------------------------
    # 3b. Add gadgets exclusive to other tools (tails lcsajdump missed)
    # ------------------------------------------------------------------
    if coverage is not None:
        tail_sets     = coverage["tail_sets"]
        lcsaj_tails   = tail_sets.get("lcsaj", set())

        for tool in ("ropper", "ropgadget", "rp_plus"):
            tool_tails = tail_sets.get(tool, set())
            # Tails that this tool seeds from but lcsajdump has NO gadget ending at
            exclusive_tails = tool_tails - lcsaj_tails

            for tail_addr in exclusive_tails:
                if tail_addr not in addr_to_node:
                    continue
                result = _reconstruct_gadget(tail_addr, addr_to_node, gm.reverse_graph)
                if result is None:
                    continue
                path, sig, total_insns = result

                # Score and classify via finder
                try:
                    score = finder.score_gadget(path)
                    tag, category = finder._classify_gadget(path)
                except Exception:
                    score, tag, category = 0, "EXTERNAL", "Sequential"

                gidx = len(gadgets)
                entry = {
                    "id":           gidx,
                    "signature":    sig,
                    "path":         [hex(a) for a in path],
                    "score":        score,
                    "tag":          tag,
                    "category":     category,
                    "duplicates":   [hex(tail_addr)],
                    "insn_count":   total_insns,
                    "exclusive_to": tool,
                }
                gadgets.append(entry)

                # Back-fill gadget_ids on path nodes
                for a in path:
                    h = hex(a)
                    if h in node_map:
                        node_map[h]["gadget_ids"].append(gidx)

    # Sort by score descending so the sidebar doesn't need to sort
    gadgets.sort(key=lambda g: g["score"], reverse=True)

    # Cap exported gadgets for large graphs to keep the JSON loadable
    _GADGET_CAP = 500
    total_gadgets_uncapped = len(gadgets)
    gadgets_capped = len(gadgets) > _GADGET_CAP
    if gadgets_capped:
        gadgets = gadgets[:_GADGET_CAP]

    for i, g in enumerate(gadgets):
        g["id"] = i

    # ------------------------------------------------------------------
    # 4. Assemble and write
    # ------------------------------------------------------------------
    meta = {
        "binary":        os.path.basename(binary_path),
        "arch":          arch,
        "timestamp":     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version":       "1.2.1",
        "total_blocks":  len(node_map),
        "total_edges":   len(links),
        "total_gadgets": total_gadgets_uncapped,
    }
    if gadgets_capped:
        meta["gadgets_capped"]          = True
        meta["gadgets_exported"]        = len(gadgets)
    if coverage is not None:
        meta["has_comparison"] = True
        meta["simulated_tools"] = coverage.get("simulated", [])
        meta["tool_versions"]   = coverage.get("tool_versions", {})

    # Skip animation for very large graphs (too expensive + large output)
    _include_animation = trace is not None and len(node_map) <= 15000
    if _include_animation:
        meta["has_animation"] = True

    output = {
        "metadata": meta,
        "nodes":    list(node_map.values()),
        "links":    links,
        "gadgets":  gadgets,
    }

    if _include_animation:
        output["animation_trace"] = trace
        output["phase_map"] = {str(k): v for k, v in (phase_map or {}).items()}

    # Use compact JSON for large graphs to halve file size
    _large = len(node_map) > 1000
    with open(output_path, "w") as fh:
        if _large:
            json.dump(output, fh, separators=(',', ':'))
        else:
            json.dump(output, fh, indent=2)
