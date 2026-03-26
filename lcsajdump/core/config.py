import capstone

ARM64_ARCH = capstone.CS_ARCH_AARCH64 if hasattr(capstone, "CS_ARCH_AARCH64") else capstone.CS_ARCH_ARM64

ARCH_PROFILES = {
    "riscv64": {
        "name": "RISC-V 64-bit",
        "cs_arch": capstone.CS_ARCH_RISCV,
        "cs_mode": capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC,
        "step": 2,
        
        "jump_mnems": {'j', 'jal', 'c.j', 'c.jal', 'jr', 'jalr', 'c.jr', 'c.jalr', 'ret', 'ecall'},
        "unconditional_jumps": {'j', 'jal', 'c.j', 'c.jal', 'ret', 'jr', 'c.jr', 'jalr', 'c.jalr', 'ecall'},
        "ret_mnems": {'ret', 'c.jr', 'jr', 'jalr', 'c.jalr', 'ecall'},
        "branch_prefixes": ('b', 'c.b'),
        "call_mnems": {'jal', 'c.jal', 'jalr', 'c.jalr'},
        
        "link_reg": "ra",           
        "primary_arg_reg": "a0",
        "frame_reg": "s0",
        "trampoline_mnems": {'j', 'c.j', 'jal', 'c.jal'},
        
        "scoring_weights": {
            "base_score": 100,
            "insn_penalty": 2,
            "bonus_link_reg": 50,
            "bonus_arg_reg": 40,
            "bonus_frame_reg": 30,
            "penalty_internal_call": 150,
            "bonus_trampoline": 30,
            "penalty_bad_ret": 20,
            "bonus_direct_call": 0
        }
    },
    "x86_64": {
        "name": "x86-64",
        "cs_arch": capstone.CS_ARCH_X86,
        "cs_mode": capstone.CS_MODE_64,
        "step": 1,
        
        "jump_mnems": {'jmp', 'call', 'ret', 'retf', 'iret', 'syscall', 'sysenter', 'int'},
        "unconditional_jumps": {'jmp', 'call', 'ret', 'retf', 'iret', 'syscall', 'sysenter', 'int'},
        "ret_mnems": {'ret', 'retn', 'retf', 'iret', 'syscall', 'int', 'sysenter'},
        "branch_prefixes": ('j', 'loop'), 
        "call_mnems": {'call'},
        
        "link_reg": {"rip", "rsp"}, 
        "primary_arg_reg": "rdi",
        "frame_reg": "rbp",
        "trampoline_mnems": {'jmp', 'call'},
        
        "scoring_weights": {
            "base_score": 100,
            "insn_penalty": 5,
            "bonus_link_reg": 30,
            "bonus_arg_reg": 60,
            "bonus_frame_reg": 40,
            "penalty_internal_call": 200,
            "bonus_trampoline": 20,
            "penalty_bad_ret": 0,
            "bonus_direct_call": 15
        }
    },
"arm64": {
        "name": "ARM64 (AArch64)",
        "cs_arch": ARM64_ARCH, 
        "cs_mode": capstone.CS_MODE_ARM,
        "step": 4,
        
        "jump_mnems": {'b', 'bl', 'br', 'blr', 'ret', 'svc'},
        "unconditional_jumps": {'b', 'bl', 'br', 'blr', 'ret', 'svc'},
        "ret_mnems": {'ret', 'svc'}, 
        "branch_prefixes": ('b.', 'cbz', 'cbnz', 'tbz', 'tbnz'), 
        "call_mnems": {'bl', 'blr'},
        
        "link_reg": {"x30", "lr"}, 
        "primary_arg_reg": "x0",
        "frame_reg": "x29",
        "trampoline_mnems": {'b', 'bl', 'br', 'blr'},
        
        "scoring_weights": {
            "base_score": 100,
            "insn_penalty": 12,
            "bonus_link_reg": 50,
            "bonus_arg_reg": 60,
            "bonus_frame_reg": 30,
            "penalty_internal_call": 150,
            "bonus_trampoline": 20,
            "penalty_bad_ret": 40,
            "bonus_direct_call": 0
        }
    }
}