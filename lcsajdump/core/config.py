import capstone

ARM64_ARCH = (
    capstone.CS_ARCH_AARCH64
    if hasattr(capstone, "CS_ARCH_AARCH64")
    else capstone.CS_ARCH_ARM64
)

ARCH_PROFILES = {
    "riscv64": {
        "name": "RISC-V 64-bit",
        "cs_arch": capstone.CS_ARCH_RISCV,
        "cs_mode": capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC,
        "step": 2,
        "jump_mnems": {
            "j",
            "jal",
            "c.j",
            "c.jal",
            "jr",
            "jalr",
            "c.jr",
            "c.jalr",
            "ret",
            "ecall",
        },
        "unconditional_jumps": {
            "j",
            "jal",
            "c.j",
            "c.jal",
            "ret",
            "jr",
            "c.jr",
            "jalr",
            "c.jalr",
            "ecall",
        },
        "ret_mnems": {"ret", "c.jr", "jr", "jalr", "c.jalr", "ecall"},
        "syscall_mnems": frozenset({"ecall"}),
        "branch_prefixes": ("b", "c.b"),
        "call_mnems": {"jal", "c.jal", "jalr", "c.jalr"},
        "link_reg": "ra",
        "primary_arg_reg": "a0",
        "frame_reg": "s0",
        "trampoline_mnems": {"j", "c.j", "jal", "c.jal"},
        "pivot_always_mnems": frozenset(),
        "pivot_sp_mnems": frozenset({"mv", "c.mv", "addi", "c.addi"}),
        "stack_pointer_reg": "sp",
        # Optuna unified, dataset v14, 26 groups, 200 trials (NDCG@5 improved +0.989)
        "scoring_weights": {
          "base_score": 100,
          "insn_penalty": 12,
          "bonus_link_reg": 1,
          "bonus_arg_reg": 1,
          "bonus_frame_reg": 1,
          "penalty_internal_call": 1,
          "bonus_trampoline": 1,
          "penalty_bad_ret": 854,
          "bonus_direct_call": 35,
          "bonus_pivot": 1,
          "bonus_syscall": 123
        },
        "search_params": {
          "limit": 5,
          "darkness": 14,
          "d": 17,
          "i": 44,
          "m": 19
        },
    },
    "x86_64": {
        "name": "x86-64",
        "cs_arch": capstone.CS_ARCH_X86,
        "cs_mode": capstone.CS_MODE_64,
        "step": 1,
        "jump_mnems": {
            "jmp",
            "call",
            "ret",
            "retf",
            "iret",
            "syscall",
            "sysenter",
            "int",
        },
        "unconditional_jumps": {
            "jmp",
            "call",
            "ret",
            "retf",
            "iret",
            "syscall",
            "sysenter",
            "int",
        },
        "ret_mnems": {"ret", "retn", "retf", "iret", "syscall", "int", "sysenter"},
        "syscall_mnems": frozenset({"syscall", "sysenter", "int"}),
        "branch_prefixes": ("j", "loop"),
        "call_mnems": {"call"},
        "link_reg": {"rip", "rsp"},
        "primary_arg_reg": "rdi",
        "frame_reg": "rbp",
        "trampoline_mnems": {"jmp", "call"},
        "pivot_always_mnems": frozenset({"leave"}),
        "pivot_sp_mnems": frozenset(
            {"xchg", "pop"}
        ),  # Rimosso 'mov' per evitare falsi positivi su prologhi funzione
        "stack_pointer_reg": "rsp",
        # Optuna unified, dataset v14, 26 groups, 200 trials (NDCG@5 improved +0.473)
        "scoring_weights": {
          "base_score": 100,
          "insn_penalty": 140,
          "bonus_link_reg": 1,
          "bonus_arg_reg": 1,
          "bonus_frame_reg": 1,
          "penalty_internal_call": 1,
          "bonus_trampoline": 1,
          "penalty_bad_ret": 649,
          "bonus_direct_call": 10,
          "bonus_pivot": 1,
          "bonus_syscall": 0
        },
        "search_params": {
            "limit": 5,
            "darkness": 6,
            "d": 12,
            "i": 128,
            "m": 21
        },
    },
    "x86_32": {
        "name": "x86-32",
        "cs_arch": capstone.CS_ARCH_X86,
        "cs_mode": capstone.CS_MODE_32,
        "step": 1,
        "jump_mnems": {
            "jmp",
            "call",
            "ret",
            "retf",
            "iret",
            "int",
        },
        "unconditional_jumps": {
            "jmp",
            "call",
            "ret",
            "retf",
            "iret",
            "int",
        },
        "ret_mnems": {"ret", "retn", "retf", "iret", "int"},
        "syscall_mnems": frozenset({"int"}),  # int 0x80
        "branch_prefixes": ("j", "loop"),
        "call_mnems": {"call"},
        "link_reg": {"eip", "esp"},
        "primary_arg_reg": "eax",
        "frame_reg": "ebp",
        "trampoline_mnems": {"jmp", "call"},
        "pivot_always_mnems": frozenset({"leave"}),
        "pivot_sp_mnems": frozenset({"xchg", "pop"}),
        "stack_pointer_reg": "esp",
        # Optuna unified, dataset v14, 26 groups, 200 trials (NDCG@5 improved +0.700)
        "scoring_weights": {
          "base_score": 100,
          "insn_penalty": 21,
          "bonus_link_reg": 1,
          "bonus_arg_reg": 1,
          "bonus_frame_reg": 1,
          "penalty_internal_call": 1,
          "bonus_trampoline": 1,
          "penalty_bad_ret": 738,
          "bonus_direct_call": 15,
          "bonus_pivot": 1,
          "bonus_syscall": 56
        },
        "search_params": {
          "limit": 5,
          "darkness": 9,
          "d": 13,
          "i": 35,
          "m": 9
        },
    },
    "arm64": {
        "name": "ARM64 (AArch64)",
        "cs_arch": ARM64_ARCH,
        "cs_mode": capstone.CS_MODE_ARM,
        "step": 4,
        "jump_mnems": {"b", "bl", "br", "blr", "ret", "svc"},
        "unconditional_jumps": {"b", "bl", "br", "blr", "ret", "svc"},
        "ret_mnems": {"ret", "svc"},
        "syscall_mnems": frozenset({"svc"}),
        "branch_prefixes": ("b.", "cbz", "cbnz", "tbz", "tbnz"),
        "call_mnems": {"bl", "blr"},
        "link_reg": {"x30", "lr"},
        "primary_arg_reg": "x0",
        "frame_reg": "x29",
        "trampoline_mnems": {"b", "bl", "br", "blr"},
        "pivot_always_mnems": frozenset(),
        "pivot_sp_mnems": frozenset({"mov", "add", "sub"}),
        "stack_pointer_reg": "sp",
        # Optuna unified, dataset v14, 26 groups, 200 trials (NDCG@5 improved +0.384)
        "scoring_weights": {
          "base_score": 100,
          "insn_penalty": 15,
          "bonus_link_reg": 1,
          "bonus_arg_reg": 1,
          "bonus_frame_reg": 1,
          "penalty_internal_call": 1,
          "bonus_trampoline": 1,
          "penalty_bad_ret": 685,
          "bonus_direct_call": 0,
          "bonus_pivot": 1,
          "bonus_syscall": 127
        },
        "search_params": {
          "limit": 5,
          "darkness": 4,
          "d": 12,
          "i": 164,
          "m": 29
        },

    },
}
