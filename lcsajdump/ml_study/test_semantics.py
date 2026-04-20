import sys
import os

from lcsajdump_dbg.ml.semantic_features import extract_semantic_features

def test():
    bin_path = "rop_emporium_bins/ret2win/ret2win"
    # Find a simple gadget: pop rdi; ret
    # Use objdump to find it quickly: objdump -d rop_emporium_bins/ret2win/ret2win | grep "pop    %rdi" -A 1
    # 4007b3:       5f                      pop    %rdi
    # 4007b4:       c3                      retq 
    addr = 0x4007b3
    size = 2
    feats = extract_semantic_features(bin_path, addr, size, "x86_64")
    print(f"Features for pop rdi; ret: {feats}")

if __name__ == "__main__":
    test()
