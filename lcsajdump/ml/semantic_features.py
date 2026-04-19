"""
semantic_features.py — Symbolic execution for deep semantic feature extraction.

Uses angr to determine the real effect of a gadget on the CPU state, bypassing
obfuscation and syntactic differences.

Features extracted:
- sm_controls_rdi (or arch equivalent): Does the gadget allow controlling the primary arg register?
- sm_stack_pivot_size: Concrete delta in the stack pointer.
- sm_writes_memory: True if any concrete or symbolic write to memory occurs.
"""

from __future__ import annotations

import logging
import os
import sys

# Suppress angr warnings for cleaner output
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)

def extract_semantic_features(binary_path: str, gadget_addr: int, gadget_size: int, arch: str) -> dict:
    """
    Given a gadget address and size, symbolically execute it using angr.
    Returns a dict of semantic features.
    """
    try:
        import angr
        import claripy
    except ImportError:
        # Fallback if angr is not installed
        return {
            "sm_controls_arg_reg": 0,
            "sm_stack_pivot_size": 0,
            "sm_writes_memory": 0
        }

    # Default fallback features
    feats = {
        "sm_controls_arg_reg": 0,
        "sm_stack_pivot_size": 0,
        "sm_writes_memory": 0
    }

    try:
        # Create a barebone angr project
        proj = angr.Project(binary_path, auto_load_libs=False)
        
        # Determine arch-specific registers
        arg_reg = "rdi" if arch == "x86_64" else "x0" if arch == "arm64" else "a0"
        sp_reg = "rsp" if arch == "x86_64" else "sp"

        # Initialize a blank state at the gadget address
        # We need to make sure the stack is fully symbolic so we can detect if rdi takes a value from it
        state = proj.factory.blank_state(addr=gadget_addr)
        
        # Inject symbolic data onto the stack
        sp = state.solver.eval(state.regs.sp)
        for i in range(16):
            sym_var = claripy.BVS(f"stack_var_{i}", 64)
            state.memory.store(sp + (i * 8), sym_var)

        # Record initial stack pointer to calculate pivot size later
        initial_sp = state.solver.eval(getattr(state.regs, sp_reg))

        # Setup simulation manager and run for exactly the gadget length/blocks
        # It's better to step through it manually to control execution
        simgr = proj.factory.simgr(state)
        
        # Step until we hit a return, jump, or run out of bounds (or too many steps)
        steps = 0
        
        # We need to tell angr not to stop at unconstrained jumps
        simgr = proj.factory.simgr(state, save_unconstrained=True)
        
        while (simgr.active or simgr.unconstrained) and steps < 10:
            simgr.step()
            steps += 1
            if simgr.unconstrained:
                # We hit an unconstrained jump (like ret with symbolic stack)
                break
            
        # We check the deadended states (e.g. hit ret) or active states
        final_state = None
        if simgr.unconstrained:
            final_state = simgr.unconstrained[0]
        elif simgr.deadended:
            final_state = simgr.deadended[0]
        elif simgr.active:
            final_state = simgr.active[0]
            
        if final_state:
            # Check stack pivot
            # Sometimes SP is symbolic if we pivoted to a symbolic value
            sp_val = getattr(final_state.regs, sp_reg)
            if not sp_val.symbolic:
                final_sp = final_state.solver.eval(sp_val)
                feats["sm_stack_pivot_size"] = final_sp - initial_sp
            else:
                feats["sm_stack_pivot_size"] = -1 # Symbolic pivot!
            
            # Check if arg_reg is symbolic (controlled by input)
            arg_val = getattr(final_state.regs, arg_reg)
            
            # Print for debug when not zero
            if arg_val.symbolic:
                # If it's symbolic, there's a very high chance we control it,
                # but let's be less strict than string matching variable names
                # since angr might simplify or rename them
                feats["sm_controls_arg_reg"] = 1
                
            # Check memory writes (simplified: inspect action log)
            for action in final_state.history.actions:
                if action.type == "mem" and action.action == "write":
                    feats["sm_writes_memory"] = 1
                    break

    except Exception as e:
        # Return fallback on any analysis failure
        pass
        
    return feats
