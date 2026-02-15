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
    }
}