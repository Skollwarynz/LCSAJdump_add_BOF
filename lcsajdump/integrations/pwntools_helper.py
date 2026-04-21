from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

# Mnemonics that can act as JOP trampolines when their operand is a register.
_TRAMPOLINE_MNEMS = {
    # x86-64
    'call', 'jmp',
    # ARM64
    'blr', 'br',
    # RISC-V
    'jalr', 'jr',
}

# Operand patterns that indicate an indirect register target (not a direct address).
# Matches: rax, rbx, r12, x0, x30, ra, t0, a0, *rax, [rax], qword ptr [rax], etc.
_REG_OPERAND_RE = re.compile(
    r'^\*?(?:qword ptr \[)?'         # optional prefix: *, qword ptr [
    r'([a-z][a-z0-9]{0,4})'          # register name
    r'(?:\s*[+\-]\s*\S+)?'           # optional offset
    r'\]?$',                          # optional closing bracket
    re.IGNORECASE,
)


_LDP_RE = re.compile(
    r'^(\w+),\s*(\w+),\s*\[sp(?:,\s*#?(-?\w+))?\](?:,\s*#?(-?\w+))?$',
    re.IGNORECASE)
_LDR_SP_RE = re.compile(
    r'^(\w+),\s*\[sp(?:,\s*#?(-?\w+))?\](?:,\s*#?(-?\w+))?$',
    re.IGNORECASE)
_LD_SP_RE = re.compile(      # RISC-V: lw/ld reg, off(sp)
    r'^(\w+),\s*-?\w+\(sp\)$',
    re.IGNORECASE)
_POP_RE = re.compile(r'^\{?(\w+)', re.IGNORECASE)


def _stack_pops(instructions: list) -> list:
    """Return register names loaded from the stack, in order.

    Handles: pop reg (x86) / ldr reg,[sp,...] / ldp r1,r2,[sp,...] (ARM64)
             lw/ld reg,N(sp) (RISC-V)
    """
    result = []
    for insn in instructions:
        mnem = insn.get('mnemonic', '').lower()
        op = insn.get('op_str', '')
        if mnem == 'pop':
            m = _POP_RE.match(op)
            if m:
                result.append(m.group(1).lower())
        elif mnem == 'ldp':
            m = _LDP_RE.match(op)
            if m:
                result.append(m.group(1).lower())
                result.append(m.group(2).lower())
        elif mnem in ('ldr', 'ldur'):
            m = _LDR_SP_RE.match(op)
            if m:
                result.append(m.group(1).lower())
        elif mnem in ('lw', 'ld', 'c.lw', 'c.ld'):
            m = _LD_SP_RE.match(op)
            if m:
                result.append(m.group(1).lower())
    return result


@dataclass
class Gadget:
    address: int
    type: str
    tag: str
    score: int
    instructions: list
    duplicate_addresses: list = field(default_factory=list)
    _lookup: dict = field(default=None, repr=False, compare=False)

    @property
    def all_addresses(self) -> list:
        return [self.address] + self.duplicate_addresses

    @property
    def trampoline_target(self) -> Optional[str]:
        """Register name if this gadget ends with an indirect call/jmp to a register, else None.

        Examples:
            call rax        -> 'rax'
            jmp qword ptr [rbx] -> 'rbx'
            blr x0          -> 'x0'
            jalr ra         -> 'ra'
            call 0x401030   -> None   (direct address, not a trampoline)
        """
        if not self.instructions:
            return None
        last = self.instructions[-1]
        mnem = last.get('mnemonic', '').lower()
        if mnem not in _TRAMPOLINE_MNEMS:
            return None
        op = last.get('op_str', '').strip()
        if not op:
            return None
        # Direct address (e.g. call 0x401176) -- return the address string as-is.
        # These are valid trampolines in the lcsajdump context (call rel32 / E8).
        if re.match(r'^0x[0-9a-f]+$', op, re.IGNORECASE) or re.match(r'^\d+$', op):
            return op
        # Indirect register operand (e.g. call rax, jmp qword ptr [rbx])
        m = _REG_OPERAND_RE.match(op)
        if m:
            return m.group(1).lower()
        return None

    @property
    def is_trampoline(self) -> bool:
        """True if this gadget ends with a call/jmp (direct or indirect)."""
        return self.trampoline_target is not None

    @property
    def target_gadget(self) -> Optional[Gadget]:
        """If this trampoline calls a direct address that is another gadget, return it."""
        target = self.trampoline_target
        if target is None or self._lookup is None:
            return None
        try:
            addr = int(target, 16) if target.lower().startswith('0x') else int(target)
        except (ValueError, TypeError):
            return None  # register operand like 'rax'
        return self._lookup.get(addr)

    @property
    def is_chained(self) -> bool:
        """True if this trampoline's direct target is another gadget in the collection."""
        return self.target_gadget is not None

    def __str__(self) -> str:
        insn_text = '; '.join(
            (i['mnemonic'] + (' ' + i['op_str'] if i['op_str'] else '')).strip()
            for i in self.instructions
        )
        also = ''
        if self.duplicate_addresses:
            also = f"  (also at {[hex(a) for a in self.duplicate_addresses]})"
        return f"0x{self.address:x}: {insn_text}{also}"

    def __repr__(self) -> str:
        return f"<Gadget 0x{self.address:x} tag={self.tag} score={self.score}>"

    # ── Item 2: Chainability ──────────────────────────────────────────────────

    def chains_to(self, other: 'Gadget') -> bool:
        """True if this gadget's tail can dispatch to other.

        - ret / svc / ecall / syscall: stack-driven — always True (any gadget follows).
        - call 0xADDR / bl #imm: True if target address == other.address.
        - jmp/blr/br indirect register: True (optimistic — caller loads the register).
        """
        target = self.trampoline_target
        if target is None:
            # Gadget ends with ret/svc/ecall — stack driven, chains to anything.
            last = self.instructions[-1] if self.instructions else {}
            mnem = last.get('mnemonic', '').lower()
            _RET_LIKE = {'ret', 'retn', 'retf', 'iret', 'svc', 'ecall', 'syscall',
                         'sysenter', 'c.jr', 'jr'}
            return mnem in _RET_LIKE
        # Direct address target (call rel32 / bl #imm)
        if target.startswith('0x') or target.isdigit():
            try:
                addr = int(target, 16) if target.startswith('0x') else int(target)
                return addr == other.address or addr in other.duplicate_addresses
            except ValueError:
                pass
        # Indirect register (jmp rax, blr x0, jalr ra) — optimistic
        return True

    # ── Item 3: Side-effect / liveness ───────────────────────────────────────

    # Mnemonics whose first operand is a memory destination, not a register write.
    _STORE_MNEMS = frozenset({
        'str', 'stp', 'stm', 'stmia', 'stmdb', 'push',
        'sw', 'sd', 'sh', 'sb', 'c.sw', 'c.sd', 'c.swsp', 'c.sdsp',
        'st', 'fst', 'movnti',
    })

    def clobbered_registers(self) -> set[str]:
        """Set of registers written by this gadget's instructions.

        Uses a heuristic: for most ISAs the destination is the first token
        before the first comma in op_str, provided the mnemonic is not a store.
        """
        written = set()
        _REG_RE = re.compile(r'^([a-z][a-z0-9]{0,4})$', re.IGNORECASE)
        for insn in self.instructions:
            mnem = insn.get('mnemonic', '').lower()
            if mnem in self._STORE_MNEMS:
                continue
            op_str = insn.get('op_str', '')
            if not op_str:
                continue
            # First token before first comma
            first = op_str.split(',')[0].strip().lstrip('*').lower()
            # Strip bracket prefixes like [sp or qword ptr [rax
            first = first.lstrip('[').split('[')[-1].strip()
            if _REG_RE.match(first):
                written.add(first)
        return written

    # ── Item 4: Stack frame layout ────────────────────────────────────────────

    # ── Item 5: Sub-sequence entry points ─────────────────────────────────────

    def entry_points(self) -> list[int]:
        """Return all addresses where this gadget can be entered.

        First entry is self.address (full gadget).  Additional entries are
        instruction boundaries where a harmless setup prefix ends (frame pointer
        setup, callee-save pushes/stps) — i.e., where entering mid-gadget still
        gives a useful sequence.
        """
        if not self.instructions:
            return [self.address]

        _HARMLESS_MNEMS = {
            # x86: frame/save setup
            'push', 'endbr64', 'endbr32',
            # ARM64: callee-save prologue
            'stp', 'str',
            # RISC-V: stack saves
            'sd', 'sw', 'addi',   # addi s0, sp, N is frame setup
            # Generic frame pointer setup
            'mov', 'movl', 'movq',
        }

        _FRAME_SETUP_RE = re.compile(
            r'(?:rbp|x29|s0|fp)\s*,\s*(?:rsp|sp)',
            re.IGNORECASE)

        entries = [self.address]
        for i, insn in enumerate(self.instructions[:-1]):  # never skip the tail
            mnem = insn.get('mnemonic', '').lower()
            op = insn.get('op_str', '')
            is_harmless = (
                mnem in _HARMLESS_MNEMS
                or bool(_FRAME_SETUP_RE.search(op))
            )
            if not is_harmless:
                break
            # Use the real address of the next instruction (correct for variable-length ISAs)
            next_insn = self.instructions[i + 1]
            try:
                next_addr = int(next_insn.get('address', '0x0'), 16)
                if next_addr and next_addr != self.address and next_addr not in entries:
                    entries.append(next_addr)
            except (ValueError, TypeError):
                pass

        return entries


def _parse_gadgets(data: dict) -> list:
    gadgets = []
    for key in ('sequential', 'jump_based'):
        for entry in data.get(key, []):
            addr = int(entry['primary_address'], 16)
            dup_addrs = [int(a, 16) for a in entry.get('duplicate_addresses', [])]
            gadgets.append(Gadget(
                address=addr,
                type=entry['type'],
                tag=entry['tag'],
                score=entry['score'],
                instructions=entry.get('instructions', []),
                duplicate_addresses=dup_addrs,
            ))
    return gadgets


class LCSAJGadgets:
    def __init__(self, binary_path: str, arch: str = 'auto', bad_chars: str = '',
                 depth: int = 20, darkness: int = 5, instructions: int = 15,
                 all_exec: bool = False, algo: bool = False):
        self._gadgets = self._run(binary_path, arch=arch, bad_chars=bad_chars,
                                  depth=depth, darkness=darkness,
                                  instructions=instructions, all_exec=all_exec,
                                  algo=algo)
        self._build_lookup()

    @classmethod
    def from_json(cls, path: str) -> 'LCSAJGadgets':
        with open(path, 'r') as f:
            data = json.load(f)
        instance = cls.__new__(cls)
        instance._gadgets = _parse_gadgets(data)
        instance._build_lookup()
        return instance

    @classmethod
    def from_json_string(cls, json_str: str) -> 'LCSAJGadgets':
        """Load gadgets from a JSON string (e.g. the output of lcsajdump-dbg --json)."""
        data = json.loads(json_str)
        instance = cls.__new__(cls)
        instance._gadgets = _parse_gadgets(data)
        instance._build_lookup()
        return instance

    def _build_lookup(self):
        addr_map = {}
        for g in self._gadgets:
            for addr in g.all_addresses:
                addr_map[addr] = g
        for g in self._gadgets:
            g._lookup = addr_map

    @staticmethod
    def _run(binary_path: str, arch: str = 'auto', bad_chars: str = '',
             depth: int = 20, darkness: int = 5, instructions: int = 15,
             all_exec: bool = False, algo: bool = False) -> list:
        cmd = [
            sys.executable, '-m', 'lcsajdump.cli',
            binary_path,
            '--json',
            '--limit', '999999',
            '--depth', str(depth),
            '--darkness', str(darkness),
            '--instructions', str(instructions),
        ]
        if arch != 'auto':
            cmd += ['--arch', arch]
        if bad_chars:
            cmd += ['--bad-chars', bad_chars]
        if all_exec:
            cmd += ['--all-exec']
        if algo:
            cmd += ['--algo']

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"lcsajdump CLI failed (exit {result.returncode}):\n{result.stderr}"
            )

        stdout = result.stdout
        start = stdout.find('{')
        if start == -1:
            raise RuntimeError(f"No JSON found in CLI output:\n{stdout}")
        data = json.loads(stdout[start:])
        return _parse_gadgets(data)

    def get(self, address: int) -> Optional[Gadget]:
        """Return the Gadget at the given address, or None if not found."""
        return self._lookup.get(address)

    def all(self) -> list[Gadget]:
        return list(self._gadgets)

    def sequential(self) -> list[Gadget]:
        """Return only Sequential-type gadgets."""
        return [g for g in self._gadgets if g.type == 'Sequential']

    def jump_based(self) -> list[Gadget]:
        """Return only Jump-Based-type gadgets."""
        return [g for g in self._gadgets if g.type == 'Jump-Based']

    def by_tag(self, tag: str) -> list[Gadget]:
        tag_upper = tag.upper()
        return [g for g in self._gadgets if g.tag.upper() == tag_upper]

    def trampolines(self, mnem: str = None, pattern: str = None) -> list[Gadget]:
        """Return gadgets that end with a call/jmp (direct or indirect).

        Args:
            mnem:    optional mnemonic filter, e.g. 'call', 'jmp', 'blr'.
            pattern: optional substring filter on the full instruction text.
        """
        result = [g for g in self._gadgets if g.is_trampoline]
        if mnem:
            mnem_lower = mnem.lower()
            result = [g for g in result
                      if g.instructions[-1].get('mnemonic', '').lower() == mnem_lower]
        if pattern:
            pattern_lower = pattern.lower()
            result = [g for g in result if pattern_lower in str(g).lower()]
        return sorted(result, key=lambda g: (g.is_chained, g.score), reverse=True)

    def find(self, pattern: str) -> list[int]:
        pattern_lower = pattern.lower()
        addrs = set()
        for gadget in self._gadgets:
            full_text = ' '.join(
                (i['mnemonic'] + ' ' + i['op_str']).strip()
                for i in gadget.instructions
            ).lower()
            if pattern_lower in full_text:
                for addr in gadget.all_addresses:
                    addrs.add(addr)
        return sorted(addrs)

    def best(self, pattern: str) -> Optional[Gadget]:
        pattern_lower = pattern.lower()
        best_gadget = None
        for gadget in self._gadgets:
            full_text = ' '.join(
                (i['mnemonic'] + ' ' + i['op_str']).strip()
                for i in gadget.instructions
            ).lower()
            if pattern_lower in full_text:
                if best_gadget is None or gadget.score > best_gadget.score:
                    best_gadget = gadget
        return best_gadget

    # ── Item 1: Register-effect search ───────────────────────────────────────

    def sets_register(self, reg: str) -> list[Gadget]:
        """Return gadgets that write to reg, sorted by score descending.

        Covers: mov reg,X / ldr reg,[...] / pop reg / ldp ...reg,... / addi reg,...
        """
        reg_lower = reg.lower()
        return sorted(
            (g for g in self._gadgets if reg_lower in g.clobbered_registers()),
            key=lambda g: g.score, reverse=True,
        )

    def loads_from_stack(self, reg: str) -> list[Gadget]:
        """Return gadgets that load reg from the stack (pop, ldr [sp,...], ldp with sp)."""
        reg_lower = reg.lower()
        return sorted(
            [g for g in self._gadgets if reg_lower in _stack_pops(g.instructions)],
            key=lambda g: g.score, reverse=True,
        )

    # ── Item 2: Chainability ──────────────────────────────────────────────────

    def find_chain(self, start: 'Gadget', end: 'Gadget', max_depth: int = 5) -> list[list[Gadget]]:
        """BFS: find sequences [start, ..., end] where each gadget chains_to the next.

        Returns up to 3 paths, shortest first.  For ret-ended gadgets (which chain
        to every other gadget) the direct path [start, end] is always returned first.
        """
        from collections import deque

        # Direct connection?
        if start.chains_to(end):
            return [[start, end]]

        paths = []
        visited_paths = set()
        queue = deque([(start, [start])])

        while queue and len(paths) < 3:
            current, path = queue.popleft()
            if len(path) >= max_depth:
                continue
            # Determine candidate next gadgets
            target = current.trampoline_target
            if target and not (target.startswith('0x') or target.isdigit()):
                # Indirect register: any gadget could follow — try top-scored
                candidates = sorted(self._gadgets, key=lambda g: g.score, reverse=True)[:30]
            elif target and current.target_gadget:
                candidates = [current.target_gadget]
            else:
                # ret-like: try all (capped)
                candidates = sorted(self._gadgets, key=lambda g: g.score, reverse=True)[:30]

            for nxt in candidates:
                if nxt in path:
                    continue
                new_path = path + [nxt]
                key = tuple(g.address for g in new_path)
                if key in visited_paths:
                    continue
                visited_paths.add(key)
                if nxt.chains_to(end):
                    paths.append(new_path + [end])
                    if len(paths) >= 3:
                        break
                else:
                    queue.append((nxt, new_path))

        return sorted(paths, key=len)

    def write_what_where(self, what_reg: str, where_reg: str) -> list[Gadget]:
        """Return gadgets that write what_reg into memory at address in where_reg.

        Covers: str/stw/sd/sw/mov [where_reg], what_reg patterns.
        Examples: str x0, [x1]  /  mov [rdi], rsi  /  sd a0, 0(a1)
        """
        what = what_reg.lower()
        where = where_reg.lower()
        _STORE_OPS = {'str', 'strb', 'strh', 'stur', 'stp',
                      'sd', 'sw', 'sh', 'sb', 'c.sd', 'c.sw',
                      'mov', 'movq', 'movl'}
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                mnem = insn.get('mnemonic', '').lower()
                op = insn.get('op_str', '').lower()
                if mnem not in _STORE_OPS:
                    continue
                if what in op and (f'[{where}' in op or f'({where})' in op):
                    result.append(g)
                    break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def zero_register(self, reg: str) -> list[Gadget]:
        """Return gadgets that reliably zero reg.

        Covers: xor reg,reg / eor reg,reg,reg / mov reg,xzr / mov reg,wzr /
                li reg,0 / mov reg,#0 / sub reg,reg,reg / and reg,reg,xzr
        """
        reg_lower = reg.lower()
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                mnem = insn.get('mnemonic', '').lower()
                op = insn.get('op_str', '').lower()
                parts = [p.strip() for p in op.split(',')]
                if not parts or parts[0] != reg_lower:
                    continue
                if mnem in ('xor', 'eor') and all(p == reg_lower for p in parts[1:] if p):
                    result.append(g)
                    break
                if mnem in ('mov', 'movz', 'movl', 'movq', 'li', 'ori') and len(parts) >= 2:
                    src = parts[1].strip().lstrip('#')
                    if src in ('xzr', 'wzr', '0', '0x0'):
                        result.append(g)
                        break
                if mnem in ('sub', 'and') and len(parts) >= 3:
                    if parts[1] == reg_lower and parts[2] in (reg_lower, 'xzr', 'wzr'):
                        result.append(g)
                        break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def call_reg(self, reg: str = None) -> list[Gadget]:
        """Return gadgets that call/jump via a register (indirect control transfer).

        Args:
            reg: optional register filter, e.g. 'rax', 'x0', 'ra'.
                 If None, returns all indirect-register trampolines.

        Covers: call rax / jmp rbx / blr x0 / br x8 / jalr ra / jr t0
        """
        result = []
        for g in self._gadgets:
            target = g.trampoline_target
            if target is None:
                continue
            if target.startswith('0x') or target.isdigit():
                continue
            if reg is None or target == reg.lower():
                result.append(g)
        return sorted(result, key=lambda g: g.score, reverse=True)

    def memory_read(self, src_reg: str, dest_reg: str = None) -> list[Gadget]:
        """Return gadgets that load from memory at [src_reg] into dest_reg.

        Args:
            src_reg:  register used as base pointer (e.g. 'x1', 'rsi', 'a1').
            dest_reg: optional destination register filter.

        Covers: ldr x0, [x1] / mov rax, [rsi] / ld a0, 0(a1)
        """
        src = src_reg.lower()
        dest = dest_reg.lower() if dest_reg else None
        _LOAD_MNEMS = {'ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldur', 'ldp',
                       'ld', 'lw', 'lh', 'lb', 'c.ld', 'c.lw',
                       'mov', 'movq', 'movl'}
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                mnem = insn.get('mnemonic', '').lower()
                op = insn.get('op_str', '').lower()
                if mnem not in _LOAD_MNEMS:
                    continue
                if f'[{src}' not in op and f'({src})' not in op:
                    continue
                if dest is not None:
                    parts = [p.strip() for p in op.split(',')]
                    if not parts or parts[0] != dest:
                        continue
                result.append(g)
                break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def pivot_gadgets(self) -> list[Gadget]:
        """Return stack pivot gadgets, sorted by score descending.

        A pivot must redirect rsp/sp to attacker-controlled data — the new value
        must come from a register or memory, NOT from an immediate constant.
        ``add rsp, 8`` and ``sub rsp, 0x20`` are NOT pivots.

        Covers:
          leave                   — mov rsp, rbp; pop rbp
          pop rsp                 — rsp ← [stack]
          xchg rsp, reg           — rsp ↔ reg  (any operand order)
          mov rsp, reg            — rsp ← reg  (non-sp source only)
          mov sp, reg / mv sp,reg — ARM64 / RISC-V
          ldr sp, [xN]            — ARM64 memory-load into sp
          ld  sp, N(reg)          — RISC-V memory-load into sp
        """
        _ALWAYS_PIVOT = {'leave'}
        _SP_NAMES = {'rsp', 'esp', 'sp'}

        def _is_immediate(s: str) -> bool:
            try:
                int(s.lstrip('#'), 0)
                return True
            except ValueError:
                return False

        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                mnem = insn.get('mnemonic', '').lower()
                op   = insn.get('op_str', '').lower()
                parts = [p.strip() for p in op.split(',')]

                # leave is always a pivot
                if mnem in _ALWAYS_PIVOT:
                    result.append(g)
                    break

                # pop rsp — rsp ← [stack]
                if mnem in ('pop', 'popq') and op.strip() in _SP_NAMES:
                    result.append(g)
                    break

                if not parts or parts[0] not in _SP_NAMES:
                    # xchg is symmetric — sp may be in either operand
                    if mnem == 'xchg' and any(p in _SP_NAMES for p in parts):
                        result.append(g)
                        break
                    continue

                # from here: parts[0] is rsp/esp/sp
                if mnem == 'xchg':
                    # xchg sp, reg
                    result.append(g)
                    break

                # mov/mv/c.mv sp, src — only if src is a register (not sp, not immediate)
                if mnem in ('mov', 'movq', 'movl', 'mv', 'c.mv') and len(parts) >= 2:
                    src = parts[1]
                    if src not in _SP_NAMES and not _is_immediate(src):
                        result.append(g)
                        break

                # ldr/ldur sp, [xN] — ARM64 load into sp
                if mnem in ('ldr', 'ldur') and len(parts) >= 2 and '[' in parts[1]:
                    result.append(g)
                    break

                # ld/lw sp, offset(reg) — RISC-V load into sp
                if mnem in ('ld', 'lw') and len(parts) >= 2 and '(' in parts[1]:
                    result.append(g)
                    break

                # add sp, reg (not sp, not immediate) — unusual but valid JOP pivot
                if mnem in ('add', 'adds') and len(parts) >= 2:
                    src = parts[-1]  # last operand: x86 add sp,reg / ARM64 add sp,sp,reg
                    if src not in _SP_NAMES and not _is_immediate(src):
                        result.append(g)
                        break

        return sorted(result, key=lambda g: g.score, reverse=True)

    def pop_chain(self, *regs) -> list[Gadget]:
        """Return gadgets that pop a specific sequence of registers from the stack.

        pop_chain('rdi') finds: pop rdi; ret
        pop_chain('rdi', 'rsi') finds: pop rdi; pop rsi; ret
        pop_chain('x19', 'x20') finds: ldp x19, x20, [sp, ...]

        Matches in-order: all requested regs must appear in _stack_pops() in the
        same order, with no unrelated regs popped in between.
        """
        if not regs:
            return []
        regs_lower = [r.lower() for r in regs]
        result = []
        for g in self._gadgets:
            popped = _stack_pops(g.instructions)
            if not popped:
                continue
            idx = 0
            for r in popped:
                if idx < len(regs_lower) and r == regs_lower[idx]:
                    idx += 1
            if idx == len(regs_lower):
                result.append(g)
        return sorted(result, key=lambda g: g.score, reverse=True)

    def reg_move(self, src_reg: str, dst_reg: str) -> list[Gadget]:
        """Return gadgets that copy src_reg into dst_reg without going via the stack.

        Covers: mov dst, src / add dst, src, #0 / orr dst, xzr, src /
                ori dst, src, 0 / mv dst, src (RISC-V)
        """
        src = src_reg.lower()
        dst = dst_reg.lower()
        _MOVE_MNEMS = {'mov', 'movl', 'movq', 'orr', 'ori', 'add', 'mv', 'c.mv'}
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                mnem = insn.get('mnemonic', '').lower()
                op = insn.get('op_str', '').lower()
                if mnem not in _MOVE_MNEMS:
                    continue
                parts = [p.strip() for p in op.split(',')]
                if not parts or parts[0] != dst:
                    continue
                # mov dst, src  /  mv dst, src  /  c.mv dst, src
                if mnem in ('mov', 'movl', 'movq', 'mv', 'c.mv') and len(parts) == 2:
                    if parts[1] == src:
                        result.append(g)
                        break
                # add dst, src, #0  /  orr dst, xzr, src  /  ori dst, src, 0
                if mnem in ('add', 'orr', 'ori') and len(parts) == 3:
                    if src in (parts[1], parts[2]) and ('0' in (parts[1], parts[2]) or 'xzr' in (parts[1], parts[2])):
                        result.append(g)
                        break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def add_register(self, dst: str, src: str = None) -> list[Gadget]:
        """Return gadgets containing an add instruction that writes to dst.

        Optionally filter by src operand (second operand on x86/ARM64/RISC-V).
        Covers: add dst, src / adds dst, src / add.w dst, src1, src2
        """
        _ADD_MNEMS = {'add', 'adds', 'add.w', 'addw'}
        dst_lower = dst.lower()
        src_lower = src.lower() if src else None
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                if insn.get('mnemonic', '').lower() not in _ADD_MNEMS:
                    continue
                parts = [p.strip().lower() for p in insn.get('op_str', '').split(',')]
                if not parts or parts[0] != dst_lower:
                    continue
                if src_lower is not None and not any(src_lower == p for p in parts[1:]):
                    continue
                result.append(g)
                break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def sub_register(self, dst: str, src: str = None) -> list[Gadget]:
        """Return gadgets containing a sub instruction that writes to dst.

        Optionally filter by src operand.
        Covers: sub dst, src / subs dst, src / sub.w dst, src1, src2
        """
        _SUB_MNEMS = {'sub', 'subs', 'sub.w', 'subw'}
        dst_lower = dst.lower()
        src_lower = src.lower() if src else None
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                if insn.get('mnemonic', '').lower() not in _SUB_MNEMS:
                    continue
                parts = [p.strip().lower() for p in insn.get('op_str', '').split(',')]
                if not parts or parts[0] != dst_lower:
                    continue
                if src_lower is not None and not any(src_lower == p for p in parts[1:]):
                    continue
                result.append(g)
                break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def or_register(self, dst: str, src: str = None) -> list[Gadget]:
        """Return gadgets containing an or/orr instruction that writes to dst.

        Covers: or dst, src / orr dst, src1, src2 / ori dst, src, imm
        """
        _OR_MNEMS = {'or', 'orr', 'ori', 'orn'}
        dst_lower = dst.lower()
        src_lower = src.lower() if src else None
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                if insn.get('mnemonic', '').lower() not in _OR_MNEMS:
                    continue
                parts = [p.strip().lower() for p in insn.get('op_str', '').split(',')]
                if not parts or parts[0] != dst_lower:
                    continue
                if src_lower is not None and not any(src_lower == p for p in parts[1:]):
                    continue
                result.append(g)
                break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def and_register(self, dst: str, src: str = None) -> list[Gadget]:
        """Return gadgets containing an and/andn instruction that writes to dst.

        Covers: and dst, src / ands dst, src1, src2 / andi dst, src, imm
        """
        _AND_MNEMS = {'and', 'ands', 'andi', 'andn'}
        dst_lower = dst.lower()
        src_lower = src.lower() if src else None
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                if insn.get('mnemonic', '').lower() not in _AND_MNEMS:
                    continue
                parts = [p.strip().lower() for p in insn.get('op_str', '').split(',')]
                if not parts or parts[0] != dst_lower:
                    continue
                if src_lower is not None and not any(src_lower == p for p in parts[1:]):
                    continue
                result.append(g)
                break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def xor_register(self, dst: str, src: str = None) -> list[Gadget]:
        """Return gadgets containing an xor/eor instruction that writes to dst.

        Note: for zeroing (xor dst, dst) use zero_register() instead.
        Covers: xor dst, src / eor dst, src1, src2 / xori dst, src, imm
        """
        _XOR_MNEMS = {'xor', 'xorq', 'xorl', 'eor', 'eors', 'xori'}
        dst_lower = dst.lower()
        src_lower = src.lower() if src else None
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                if insn.get('mnemonic', '').lower() not in _XOR_MNEMS:
                    continue
                parts = [p.strip().lower() for p in insn.get('op_str', '').split(',')]
                if not parts or parts[0] != dst_lower:
                    continue
                if src_lower is not None and not any(src_lower == p for p in parts[1:]):
                    continue
                result.append(g)
                break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def set_immediate(self, dst: str, value: int = None) -> list[Gadget]:
        """Return gadgets that load an immediate constant into dst.

        Covers:
          x86-64 : mov rax, 59  /  movl eax, 0x3b  /  movq rax, 59
          ARM64  : mov x8, #221  /  movz x8, #221
          RISC-V : li a7, 221  /  addi a7, zero, 221

        Optionally filter by exact integer value.
        """
        _IMM_MNEMS = {'mov', 'movl', 'movq', 'movz', 'movk', 'movn', 'li', 'ldi'}
        _ZERO_REGS = {'zero', 'x0', 'wzr', 'xzr'}
        dst_lower = dst.lower()
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                mnem = insn.get('mnemonic', '').lower()
                op = insn.get('op_str', '')
                parts = [p.strip() for p in op.split(',')]
                if not parts or parts[0].lower() != dst_lower:
                    continue
                imm = None
                if mnem in _IMM_MNEMS and len(parts) >= 2:
                    try:
                        imm = int(parts[1].strip().lstrip('#'), 0)
                    except ValueError:
                        pass
                elif mnem == 'addi' and len(parts) == 3:
                    # RISC-V: addi dst, zero, imm
                    if parts[1].strip().lower() in _ZERO_REGS:
                        try:
                            imm = int(parts[2].strip().lstrip('#'), 0)
                        except ValueError:
                            pass
                if imm is None:
                    continue
                if value is not None and imm != value:
                    continue
                result.append(g)
                break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def stack_delta(self, n: int) -> list[Gadget]:
        """Return gadgets whose net stack pointer adjustment (excluding the tail) equals n bytes.

        Positive n means rsp increases (stack shrinks — pops/add rsp).
        Negative n means rsp decreases (stack grows — pushes/sub rsp).

        Useful for alignment gadgets (n=8 on x86-64) and stack pivoting.

        Covers:
          x86-64 : push/pop (±8), add/sub rsp, N
          ARM64  : add/sub sp, sp, #N  /  ldp/stp [sp], #N (writeback)
          RISC-V : addi sp, sp, N
        """
        _SP_NAMES = {'rsp', 'esp', 'sp'}
        result = []
        for g in self._gadgets:
            delta = 0
            for insn in g.instructions[:-1]:  # exclude tail
                mnem = insn.get('mnemonic', '').lower()
                op = insn.get('op_str', '').lower()
                parts = [p.strip() for p in op.split(',')]
                if mnem in ('push', 'pushq', 'pushd'):
                    delta -= 8
                elif mnem in ('pop', 'popq', 'popd'):
                    if parts and parts[0] not in _SP_NAMES:
                        delta += 8
                elif mnem in ('add', 'adds', 'addi') and parts and parts[0] in _SP_NAMES:
                    try:
                        delta += int(parts[-1].lstrip('#'), 0)
                    except (ValueError, IndexError):
                        pass
                elif mnem in ('sub', 'subs') and parts and parts[0] in _SP_NAMES:
                    try:
                        delta -= int(parts[-1].lstrip('#'), 0)
                    except (ValueError, IndexError):
                        pass
                elif mnem == 'ldp':
                    # ARM64 post-indexed: ldp x1, x2, [sp], #N → sp += N
                    if '], #' in op:
                        try:
                            delta += int(op.split('], #')[1].split()[0], 0)
                        except (ValueError, IndexError):
                            pass
                elif mnem == 'stp':
                    # ARM64 pre-indexed: stp x1, x2, [sp, #-N]! → sp -= N
                    if '[sp, #' in op and op.endswith('!'):
                        try:
                            delta += int(op.split('[sp, #')[1].rstrip('!').split(']')[0], 0)
                        except (ValueError, IndexError):
                            pass
            if delta == n:
                result.append(g)
        return sorted(result, key=lambda g: g.score, reverse=True)

    def shift_register(self, dst: str, direction: str = None, amount: int = None) -> list[Gadget]:
        """Return gadgets containing a shift instruction that writes to dst.

        direction: 'left'  — shl/sal/lsl/slli
                   'right' — shr/lsr/srli (logical, zero-fill)
                   'arith' — sar/asr/srai (arithmetic, sign-extend)
                   'rot'   — rol/ror
                   None    — any shift

        amount: filter by immediate shift count (e.g. 3 for lsl x0, x0, #3).
                When None, variable shifts (shl rax, cl) are also included.
        """
        _LEFT  = {'shl', 'sal', 'shlq', 'shll', 'lsl', 'lsls', 'slli'}
        _RIGHT = {'shr', 'shrq', 'shrl', 'lsr',  'lsrs', 'srli'}
        _ARITH = {'sar', 'sarq', 'sarl', 'asr',  'asrs', 'srai'}
        _ROT   = {'rol', 'rolq', 'ror',  'rorq', 'rorl'}
        _ALL   = _LEFT | _RIGHT | _ARITH | _ROT
        if direction == 'left':
            mnems = _LEFT
        elif direction == 'right':
            mnems = _RIGHT
        elif direction == 'arith':
            mnems = _ARITH
        elif direction == 'rot':
            mnems = _ROT
        else:
            mnems = _ALL
        dst_lower = dst.lower()
        result = []
        for g in self._gadgets:
            for insn in g.instructions:
                if insn.get('mnemonic', '').lower() not in mnems:
                    continue
                parts = [p.strip().lower() for p in insn.get('op_str', '').split(',')]
                if not parts or parts[0] != dst_lower:
                    continue
                if amount is not None:
                    try:
                        if int(parts[-1].lstrip('#'), 0) != amount:
                            continue
                    except (ValueError, IndexError):
                        continue
                result.append(g)
                break
        return sorted(result, key=lambda g: g.score, reverse=True)

    def address_in_range(self, low: int, high: int) -> list[Gadget]:
        """Return gadgets whose primary address falls in [low, high).

        Useful when certain address ranges contain bad characters, or when
        narrowing results to a specific library/section after a partial leak.

        Example: gadgets.pop_chain('rdi') may return dozens; chain with
                 address_in_range to keep only gadgets below 0x410000.
        """
        return sorted(
            [g for g in self._gadgets if low <= g.address < high],
            key=lambda g: g.score, reverse=True,
        )

    def no_clobber(self, *regs) -> list[Gadget]:
        """Return gadgets that do NOT write to any of the specified registers.

        Useful when building a chain and certain registers must be preserved.

        Example: gadgets.no_clobber('x19', 'x20') returns all gadgets that
                 leave x19 and x20 untouched.
        """
        if not regs:
            return list(self._gadgets)
        regs_lower = {r.lower() for r in regs}
        return sorted(
            [g for g in self._gadgets if not (g.clobbered_registers() & regs_lower)],
            key=lambda g: g.score, reverse=True,
        )

    def gadgets_by_size(self, min_insns: int = 1, max_insns: int = 3) -> list[Gadget]:
        """Return gadgets with instruction count in [min_insns, max_insns].

        Useful for finding short, clean gadgets with minimal side effects.
        Default: 1-3 instructions (most useful for ROP chains).
        """
        return sorted(
            [g for g in self._gadgets if min_insns <= len(g.instructions) <= max_insns],
            key=lambda g: g.score, reverse=True,
        )

    def overview(self) -> None:
        """Print a summary of available gadgets grouped by semantic category.

        Shows counts per category so you know which semantic APIs are worth using
        without having to call each one individually.

        Example output::

            LCSAJGadgets overview — 142 total (98 sequential, 44 jump-based)
            ─────────────────────────────────────────────────────────────────
            Trampolines       23   call_reg() / trampolines()
            Stack pivots       5   pivot_gadgets()
            Syscall gadgets    3   find('syscall') / find('svc') / find('ecall')
            Pop chains        41   pop_chain('rdi') / loads_from_stack('rdi')
            Reg moves         12   reg_move('rax', 'rdi')
            Zero reg          8    zero_register('rax')
            Write-what-where   6   write_what_where('rsi', 'rdi')
            Memory reads      14   memory_read('rsi')
            ─────────────────────────────────────────────────────────────────
            Top tags: pop_ret(41)  ret(31)  xchg(8)  blr(6)  leave(5)
        """
        total = len(self._gadgets)
        sequential = sum(1 for g in self._gadgets if g.type == 'Sequential')
        jump_based = total - sequential

        _SYSCALL_MNEMS = {'syscall', 'svc', 'ecall', 'sysenter'}
        _STORE_OPS = {'str', 'strb', 'strh', 'stur', 'stp',
                      'sd', 'sw', 'sh', 'sb', 'c.sd', 'c.sw', 'mov', 'movq', 'movl'}
        _LOAD_OPS = {'ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldur', 'ldp',
                     'ld', 'lw', 'lh', 'lb', 'c.ld', 'c.lw', 'mov', 'movq', 'movl'}
        _MOVE_OPS = {'mov', 'movl', 'movq', 'mv', 'c.mv', 'orr', 'ori', 'add'}
        _ZERO_OPS = {'xor', 'eor', 'sub', 'and'}

        def _has_mnem(g, mnems):
            return any(insn.get('mnemonic', '').lower() in mnems for insn in g.instructions)

        def _has_mem_store(g):
            for insn in g.instructions:
                if insn.get('mnemonic', '').lower() in _STORE_OPS:
                    op = insn.get('op_str', '')
                    if '[' in op or '(' in op:
                        return True
            return False

        def _has_mem_load(g):
            for insn in g.instructions:
                if insn.get('mnemonic', '').lower() in _LOAD_OPS:
                    op = insn.get('op_str', '')
                    if '[' in op or '(' in op:
                        return True
            return False

        def _has_zero(g):
            for insn in g.instructions:
                mnem = insn.get('mnemonic', '').lower()
                op = insn.get('op_str', '').lower()
                parts = [p.strip() for p in op.split(',')]
                if mnem in ('xor', 'eor') and len(parts) >= 2 and parts[0] == parts[-1]:
                    return True
                if mnem in ('sub', 'and') and len(set(p for p in parts if p)) == 1:
                    return True
                if mnem in ('mov', 'li', 'movz') and len(parts) >= 2:
                    if parts[1].lstrip('#') in ('0', '0x0', 'xzr', 'wzr'):
                        return True
            return False

        n_trampolines = len(self.trampolines())
        n_pivots = len(self.pivot_gadgets())
        n_syscall = sum(1 for g in self._gadgets if _has_mnem(g, _SYSCALL_MNEMS))
        n_pop = sum(1 for g in self._gadgets if _stack_pops(g.instructions))
        n_reg_move = sum(1 for g in self._gadgets if _has_mnem(g, _MOVE_OPS))
        n_zero = sum(1 for g in self._gadgets if _has_zero(g))
        n_www = sum(1 for g in self._gadgets if _has_mem_store(g))
        n_memread = sum(1 for g in self._gadgets if _has_mem_load(g))

        from collections import Counter
        tag_counts = Counter(g.tag for g in self._gadgets)
        top_tags = '  '.join(f"{tag}({cnt})" for tag, cnt in tag_counts.most_common(5))

        sep = '─' * 65
        lines = [
            f"LCSAJGadgets overview — {total} total ({sequential} sequential, {jump_based} jump-based)",
            sep,
            f"  Trampolines       {n_trampolines:<5}  call_reg() / trampolines()",
            f"  Stack pivots      {n_pivots:<5}  pivot_gadgets()",
            f"  Syscall gadgets   {n_syscall:<5}  find('syscall') / find('svc') / find('ecall')",
            f"  Pop / stack loads {n_pop:<5}  pop_chain('rdi') / loads_from_stack('rdi')",
            f"  Reg moves         {n_reg_move:<5}  reg_move('rax', 'rdi')",
            f"  Zero reg          {n_zero:<5}  zero_register('rax')",
            f"  Write-what-where  {n_www:<5}  write_what_where('rsi', 'rdi')",
            f"  Memory reads      {n_memread:<5}  memory_read('rsi')",
            sep,
            f"  Top tags: {top_tags}",
        ]
        print('\n'.join(lines))

    def __len__(self) -> int:
        return len(self._gadgets)

    def __iter__(self):
        return iter(self._gadgets)
