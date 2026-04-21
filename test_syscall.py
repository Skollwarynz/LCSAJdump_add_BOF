from lcsajdump.integrations.pwntools_helper import LCSAJGadgets

try:
    print("[*] Cerco syscall in /bin/ls...")
    gadgets = LCSAJGadgets("/bin/ls")
    syscalls = gadgets.syscall()
    
    print(f"[+] Trovati {len(syscalls)} gadget con syscall!")
    for i, g in enumerate(syscalls[:3]):
        print(f"    {i+1}. {g}")
except Exception as e:
    print(f"[-] Errore: {e}")
