import sys

def patch_pwntools_helper():
    path = "/home/chris/Desktop/LCSAJdump/lcsajdump/integrations/pwntools_helper.py"
    with open(path, "r") as f:
        lines = f.readlines()
        
    # Trova il punto dove inserire (dopo pivot_gadgets per esempio)
    insert_idx = -1
    for i, line in enumerate(lines):
        if "def pivot_gadgets(self) -> list[Gadget]:" in line:
            insert_idx = i - 1
            break
            
    if insert_idx == -1:
        print("Non riesco a trovare il punto di inserimento.")
        return
        
    syscall_method = """
    def syscall(self) -> list[Gadget]:
        \"\"\"Return gadgets that perform a system call (syscall, svc, int 0x80, ecall), sorted by score.\"\"\"
        syscall_mnems = {'syscall', 'sysenter', 'svc', 'int', 'ecall'}
        result = []
        for g in self._gadgets:
            # Check if any instruction in the gadget is a syscall
            if any(i.get('mnemonic', '').lower() in syscall_mnems for i in g.instructions):
                result.append(g)
        return sorted(result, key=lambda g: g.score, reverse=True)
"""
    
    lines.insert(insert_idx, syscall_method)
    
    with open(path, "w") as f:
        f.writelines(lines)
        
    print("API syscall() aggiunta con successo!")

patch_pwntools_helper()
