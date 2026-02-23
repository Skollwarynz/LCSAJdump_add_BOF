import capstone

ARCH_PROFILES = {
    "riscv64": {
        "name": "RISC-V 64-bit",
        "cs_arch": capstone.CS_ARCH_RISCV,
        "cs_mode": capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC,
        "step": 2, # min alignment (RVC)
        
        # --- CONTROL FLOW & TERMINATORS ---
        # Istruzioni che chiudono un blocco LCSAJ
        "jump_mnems": {'j', 'jal', 'c.j', 'c.jal', 'jr', 'jalr', 'c.jr', 'c.jalr', 'ret'},
        # Istruzioni che non permettono il fallthrough (flusso sequenziale)
        "unconditional_jumps": {'j', 'jal', 'c.j', 'c.jal', 'ret', 'jr', 'c.jr', 'jalr', 'c.jalr'},
        # Istruzioni valide per terminare un gadget ROP
        "ret_mnems": {'ret', 'c.jr', 'jr', 'jalr', 'c.jalr'},
        # Prefissi per i branch condizionali
        "branch_prefixes": ('b', 'c.b'),
        
        # --- SCORING PARAMETERS ---
        "link_reg": "ra",           
        "primary_arg_reg": "a0",    
        "trampoline_mnems": {'j', 'c.j', 'jal', 'c.jal'} 
    },
    "x86_64": {
        "name": "x86-64",
        "cs_arch": capstone.CS_ARCH_X86,
        "cs_mode": capstone.CS_MODE_64,
        "step": 1, # no alignment restrictions for x86
        
        # --- CONTROL FLOW & TERMINATORS ---
        "jump_mnems": {'jmp', 'call', 'ret', 'retf', 'iret', 'syscall', 'sysenter', 'int'},
        
        # ADDED SYSCALLS HERE: Treat them as valid unconditional transfers
        "unconditional_jumps": {'jmp', 'call', 'ret', 'retf', 'iret', 'syscall', 'sysenter', 'int'},
        
        # ADDED SYSCALLS HERE: Trick the engine into treating them as valid gadget sinks
        "ret_mnems": {'ret', 'retn', 'retf', 'iret', 'syscall', 'int', 'sysenter'},
        
        "branch_prefixes": ('j', 'loop'), 
        
        # --- SCORING PARAMETERS ---
        "link_reg": {"rip", "rsp"}, 
        "primary_arg_reg": "rdi",      
        "trampoline_mnems": {'jmp', 'call'} 
    },
    "arm64": {
        "name": "ARM64 (AArch64)",
        "cs_arch": capstone.CS_ARCH_AARCH64,
        "cs_mode": capstone.CS_MODE_ARM,
        "step": 4, # Le istruzioni ARM64 sono sempre di 4 byte
        
        # --- CONTROL FLOW & TERMINATORS ---
        "jump_mnems": {'b', 'bl', 'br', 'blr', 'ret', 'svc'},
        "unconditional_jumps": {'b', 'bl', 'br', 'blr', 'ret', 'svc'},
        "ret_mnems": {'ret', 'br', 'blr', 'svc'},
        "branch_prefixes": ('b.', 'cbz', 'cbnz', 'tbz', 'tbnz'), 
        
        # --- SCORING PARAMETERS ---
        "link_reg": {"x30", "lr"}, 
        "primary_arg_reg": "x0",      
        "trampoline_mnems": {'b', 'bl', 'br', 'blr'} 
    }
}
