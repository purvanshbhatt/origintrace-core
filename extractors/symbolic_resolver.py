"""
OriginTrace — Concolic Execution Engine (SymbolicResolver)

Uses the `angr` framework to perform bounded symbolic execution on isolated
functions within a malware binary. This module targets obfuscated string
decryption loops and dynamically resolved API calls (e.g., GetProcAddress)
that defeat static decompilation.

The engine is memory-safe by design:
  - auto_load_libs=False prevents state explosion from shared library modeling.
  - Each function exploration is time-boxed to TIMEOUT_SECONDS.
  - A hard instruction ceiling (MAX_STEPS) kills runaway paths.

Academic Value (SIoU Metric):
  When angr resolves a hidden string deterministically, and the LLM
  independently infers the same string from the decompiled C-pseudocode,
  the overlap defines the Semantic Intersection over Union — a formal
  measure of the LLM's reasoning accuracy.
"""

import logging
import string
import signal
import angr
import claripy
from typing import List, Optional
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeout

logger = logging.getLogger("origintrace.symbolic")

# --- Configuration ---
TIMEOUT_SECONDS = 15      # Hard wall-clock timeout per function
MAX_STEPS = 50_000        # Maximum basic blocks before aborting
MAX_ACTIVE_STATES = 128   # Cap active states to prevent memory explosion
MIN_STRING_LENGTH = 4     # Ignore resolved strings shorter than this


class ConcolicEngine:
    """
    Bounded symbolic execution engine for resolving obfuscated artifacts.
    Initializes an angr Project with no external library loading.
    """

    def __init__(self, binary_path: str):
        """
        Args:
            binary_path: Absolute path to the PE/ELF binary on disk.
        """
        self.binary_path = binary_path
        try:
            self.project = angr.Project(
                binary_path,
                auto_load_libs=False,
                load_options={"main_opts": {"base_addr": 0x400000}}
            )
            self.cfg = None  # Lazy-loaded on demand
            logger.info(f"[ConcolicEngine] Loaded binary: {binary_path}")
        except Exception as e:
            logger.error(f"[ConcolicEngine] Failed to load binary: {e}")
            self.project = None

    def explore_function(self, start_addr: int, end_addr: Optional[int] = None) -> List[str]:
        """
        Symbolically execute a bounded function region and extract any
        printable ASCII strings resolved by the constraint solver.

        Args:
            start_addr: Entry address of the target function/basic block.
            end_addr:   Optional exit address. If None, angr will explore
                        until it hits a return or the step limit.

        Returns:
            List of resolved plaintext strings (URLs, DLL names, API names).
        """
        if not self.project:
            return []

        resolved_strings: List[str] = []

        try:
            # Create a blank state at the function entry with symbolic registers
            state = self.project.factory.blank_state(
                addr=start_addr,
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                }
            )

            # Inject symbolic bitvectors into common argument registers
            # This simulates unknown inputs to decryption routines
            sym_rcx = claripy.BVS("sym_rcx", 64)
            sym_rdx = claripy.BVS("sym_rdx", 64)
            state.regs.rcx = sym_rcx
            state.regs.rdx = sym_rdx

            # Configure the simulation manager
            simgr = self.project.factory.simgr(state)

            # Define find/avoid targets
            find_addrs = [end_addr] if end_addr else []

            # Step through the function with bounded execution
            step_count = 0
            while len(simgr.active) > 0 and step_count < MAX_STEPS:
                simgr.step()
                step_count += 1

                # Cap active states to prevent memory explosion
                if len(simgr.active) > MAX_ACTIVE_STATES:
                    simgr.active = simgr.active[:MAX_ACTIVE_STATES]

                # If we have a target end address, check for found states
                if find_addrs:
                    simgr.move(from_stash="active", to_stash="found",
                               filter_func=lambda s: s.addr in find_addrs)
                    if simgr.found:
                        break

            # Harvest strings from all terminal states
            harvest_states = simgr.found if simgr.found else simgr.deadended
            for terminal_state in harvest_states:
                resolved_strings.extend(
                    self._extract_strings_from_state(terminal_state)
                )

        except Exception as e:
            logger.warning(f"[ConcolicEngine] Exploration failed at 0x{start_addr:08x}: {e}")

        # Deduplicate and return
        return list(set(resolved_strings))

    def _extract_strings_from_state(self, state: angr.SimState) -> List[str]:
        """
        Inspect a terminal simulation state for printable ASCII strings
        in stdout, memory dumps, and register evaluations.
        """
        found: List[str] = []

        # Strategy 1: Check stdout for any printed/decrypted output
        try:
            stdout_data = state.posix.dumps(1)  # fd 1 = stdout
            decoded = stdout_data.decode("ascii", errors="ignore")
            found.extend(self._filter_printable(decoded))
        except Exception:
            pass

        # Strategy 2: Scan writable memory segments for concrete strings
        try:
            for obj in self.project.loader.all_objects:
                for seg in obj.segments:
                    if seg.is_writable and seg.memsize < 0x10000:  # cap at 64KB
                        try:
                            mem_data = state.solver.eval(
                                state.memory.load(seg.min_addr, min(seg.memsize, 1024)),
                                cast_to=bytes
                            )
                            decoded = mem_data.decode("ascii", errors="ignore")
                            found.extend(self._filter_printable(decoded))
                        except Exception:
                            continue
        except Exception:
            pass

        return found

    def _filter_printable(self, raw: str) -> List[str]:
        """
        Extract contiguous runs of printable ASCII from a raw byte string.
        Filters for IOC-like patterns: URLs, file paths, DLL names.
        """
        results = []
        current = []
        printable = set(string.printable) - set("\t\n\r\x0b\x0c")

        for ch in raw:
            if ch in printable:
                current.append(ch)
            else:
                if len(current) >= MIN_STRING_LENGTH:
                    candidate = "".join(current)
                    if self._is_interesting(candidate):
                        results.append(candidate)
                current = []

        # Flush remaining
        if len(current) >= MIN_STRING_LENGTH:
            candidate = "".join(current)
            if self._is_interesting(candidate):
                results.append(candidate)

        return results

    @staticmethod
    def _is_interesting(s: str) -> bool:
        """Heuristic filter: keep strings that look like IOCs or API names."""
        # URLs
        if s.startswith("http://") or s.startswith("https://"):
            return True
        # File/registry paths
        if "\\" in s or "/" in s:
            return True
        # DLL or API names (contain a dot or are CamelCase)
        if ".dll" in s.lower() or ".exe" in s.lower():
            return True
        # Mixed case with no spaces (likely API name like "VirtualAllocEx")
        if any(c.isupper() for c in s) and any(c.islower() for c in s) and " " not in s:
            return True
        # Long enough to be meaningful
        if len(s) >= 8:
            return True
        return False


def resolve_with_timeout(binary_path: str, start_addr: int,
                         end_addr: Optional[int] = None,
                         timeout: int = TIMEOUT_SECONDS) -> List[str]:
    """
    Top-level entrypoint for the extractor. Runs concolic execution in
    a subprocess with a hard wall-clock timeout to guarantee the API
    never hangs.

    Args:
        binary_path: Path to the binary file.
        start_addr:  Function entry address.
        end_addr:    Optional function exit address.
        timeout:     Maximum seconds before aborting.

    Returns:
        List of resolved strings, or empty list on timeout/error.
    """
    try:
        with ProcessPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_engine, binary_path, start_addr, end_addr)
            return future.result(timeout=timeout)
    except FuturesTimeout:
        logger.warning(f"[ConcolicEngine] Timeout ({timeout}s) at 0x{start_addr:08x}")
        return []
    except Exception as e:
        logger.warning(f"[ConcolicEngine] Subprocess error: {e}")
        return []


def _run_engine(binary_path: str, start_addr: int,
                end_addr: Optional[int]) -> List[str]:
    """Worker function executed in a subprocess."""
    engine = ConcolicEngine(binary_path)
    return engine.explore_function(start_addr, end_addr)
