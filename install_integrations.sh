#!/bin/bash

# LCSAJdump Integrations Installer

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --gdb       Install GDB/GEF/pwndbg plugin"
    echo "  --pwntools  Install Pwntools helper (installs lcsajdump in editable mode)"
    echo "  --ida       Install IDA Pro plugin (Placeholder)"
    echo "  --all       Install all available integrations"
    echo "  -h, --help  Show this help message"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

INSTALL_GDB=false
INSTALL_PWNTOOLS=false
INSTALL_IDA=false

for arg in "$@"; do
    case $arg in
        --gdb)
            INSTALL_GDB=true
            ;;
        --pwntools)
            INSTALL_PWNTOOLS=true
            ;;
        --ida)
            INSTALL_IDA=true
            ;;
        --all)
            INSTALL_GDB=true
            INSTALL_PWNTOOLS=true
            INSTALL_IDA=true
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "[-] Unknown option: $arg"
            usage
            ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GDB_PLUGIN="${REPO_ROOT}/lcsajdump/integrations/gdb_plugin.py"

echo "[*] Starting LCSAJdump Integrations Installer..."

if [ "$INSTALL_GDB" = true ]; then
    echo "[*] Installing GDB plugin..."
    GDBINIT="$HOME/.gdbinit"
    
    # Check if already installed
    if grep -q "gdb_plugin.py" "$GDBINIT" 2>/dev/null; then
        echo "[+] GDB plugin is already installed in $GDBINIT"
    else
        echo "" >> "$GDBINIT"
        echo "# LCSAJdump plugin" >> "$GDBINIT"
        echo "source $GDB_PLUGIN" >> "$GDBINIT"
        echo "[+] Added LCSAJdump to $GDBINIT"
    fi
fi

if [ "$INSTALL_PWNTOOLS" = true ]; then
    echo "[*] Installing Pwntools integration..."
    echo "[*] Installing LCSAJdump in editable mode so it can be imported globally..."
    if command -v pip3 &> /dev/null; then
        pip3 install -e "$REPO_ROOT"
        echo "[+] Pwntools integration installed successfully!"
        echo "[+] You can now use: from lcsajdump.integrations.pwntools_helper import LCSAJGadgets"
    else
        echo "[-] pip3 not found! Please install pip3 to set up the pwntools helper."
    fi
fi

if [ "$INSTALL_IDA" = true ]; then
    echo "[*] Installing IDA plugin..."
    # Check if IDA is installed
    IDA_DIR=""
    if [ -d "$HOME/.idapro/plugins" ]; then
        IDA_DIR="$HOME/.idapro/plugins"
    elif [ -d "$HOME/.ida/plugins" ]; then
        IDA_DIR="$HOME/.ida/plugins"
    fi
    
    if [ -n "$IDA_DIR" ]; then
        echo "[-] IDA plugin is currently a work in progress and not yet available in the repository."
        # If we had one: ln -sf "$REPO_ROOT/lcsajdump/integrations/ida_plugin.py" "$IDA_DIR/lcsajdump_ida.py"
    else
        echo "[-] IDA Pro plugins directory not found. Please install manually when available."
    fi
fi

echo "[+] Done!"
