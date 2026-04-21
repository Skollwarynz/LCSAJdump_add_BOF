from lcsajdump.integrations.pwntools_helper import LCSAJGadgets

try:
    print("[*] Running pwntools integration test...")
    gadgets = LCSAJGadgets("/bin/ls")
    print(f"[+] Successfully found {len(gadgets._gadgets)} gadgets using pwntools helper.")
except Exception as e:
    print(f"[-] Error: {e}")
