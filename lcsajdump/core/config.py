import capstone

ARCH_PROFILES = {
    "riscv64": {
        "name": "RISC-V 64-bit",
        "cs_arch": capstone.CS_ARCH_RISCV,
        "cs_mode": capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC,
        "step": 2,
        
        "jump_mnems": {'j', 'jal', 'c.j', 'c.jal', 'jr', 'jalr', 'c.jr', 'c.jalr', 'ret'},
        "unconditional_jumps": {'j', 'jal', 'c.j', 'c.jal', 'ret', 'jr', 'c.jr', 'jalr', 'c.jalr'},
        "ret_mnems": {'ret', 'c.jr', 'jr', 'jalr', 'c.jalr'},
        "branch_prefixes": ('b', 'c.b'),
        
        "link_reg": "ra",           
        "primary_arg_reg": "a0",    
        "trampoline_mnems": {'j', 'c.j', 'jal', 'c.jal'},
        
        "scoring_weights": {
            "base_score": 100,
            "insn_penalty": 2,       
            "bonus_link_reg": 50,    
            "bonus_arg_reg": 40,     
            "bonus_trampoline": 30,
            "penalty_bad_ret": 20    
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
        
        "link_reg": {"rip", "rsp"}, 
        "primary_arg_reg": "rdi",      
        "trampoline_mnems": {'jmp', 'call'},
        
        "scoring_weights": {
            "base_score": 100,
            "insn_penalty": 5,       
            "bonus_link_reg": 30,    
            "bonus_arg_reg": 60,     
            "bonus_trampoline": 20,
            "penalty_bad_ret": 0     
        }
    },
    "arm64": {
        "name": "ARM64 (AArch64)",
        "cs_arch": capstone.CS_ARCH_AARCH64,
        "cs_mode": capstone.CS_MODE_ARM,
        "step": 4,
        
        "jump_mnems": {'b', 'bl', 'br', 'blr', 'ret', 'svc'},
        "unconditional_jumps": {'b', 'bl', 'br', 'blr', 'ret', 'svc'},
        "ret_mnems": {'ret', 'br', 'blr', 'svc'},
        "branch_prefixes": ('b.', 'cbz', 'cbnz', 'tbz', 'tbnz'), 
        
        "link_reg": {"x30", "lr"}, 
        "primary_arg_reg": "x0",      
        "trampoline_mnems": {'b', 'bl', 'br', 'blr'},
        
        "scoring_weights": {
            "base_score": 100,
            "insn_penalty": 12,   
            "bonus_link_reg": 50,
            "bonus_arg_reg": 60,
            "bonus_trampoline": 20,
            "penalty_bad_ret": 40
        }
    }
}