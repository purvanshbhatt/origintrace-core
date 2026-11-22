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
  - The whole exploration runs in a child process that is terminated if it
    overruns, so a stuck solver can never hang the API.

Academic Value (SIoU Metric):
  When angr resolves a hidden string deterministically, and the LLM
  independently infers the same string from the decompiled C-pseudocode,
  the overlap defines the Semantic Intersection over Union — a formal
  measure of the LLM's reasoning accuracy.
"""

import logging
import multiprocessing
import string
import time
from typing import Any, Callable, List, Optional, Sequence, Tuple

logger = logging.getLogger("origintrace.symbolic")

# --- Configuration ---
TIMEOUT_SECONDS = 15      # Wall-clock budget for exploring one function
STARTUP_GRACE_SECONDS = 30  # Extra time for the child to import angr and load the binary
MAX_STEPS = 50_000        # Maximum basic blocks before aborting
MAX_ACTIVE_STATES = 128   # Cap active states to prevent memory explosion
MAX_HARVEST_STATES = 16   # Terminal states inspected for decrypted strings
MIN_STRING_LENGTH = 4     # Ignore resolved strings shorter than this
MEMORY_SCAN_BYTES = 4096  # Bytes read from each writable segment
_POLL_INTERVAL_SECONDS = 0.25

# Argument registers made symbolic, per architecture (Win64 ABI / x86 fastcall).
_SYMBOLIC_ARG_REGISTERS = {
    "AMD64": ("rcx", "rdx", "r8", "r9"),
    "X86": ("ecx", "edx"),
}


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
        self.project = None
        try:
            # angr is imported lazily: it is heavy and optional.
            import angr

            self._angr = angr
            # The binary is mapped at its own preferred base so that addresses
            # reported by radare2 line up with angr's address space.
            self.project = angr.Project(binary_path, auto_load_libs=False)
            logger.info(f"[ConcolicEngine] Loaded binary: {binary_path}")
        except Exception as e:
            logger.error(f"[ConcolicEngine] Failed to load binary: {e}")

    def explore_function(self, start_addr: int, end_addr: Optional[int] = None,
                         timeout: float = TIMEOUT_SECONDS) -> List[str]:
        """
        Symbolically execute a bounded function region and extract any
        printable ASCII strings resolved by the constraint solver.

        Args:
            start_addr: Entry address of the target function/basic block.
            end_addr:   Optional exit address. If None, angr will explore
                        until it hits a return or the step limit.
            timeout:    Wall-clock budget in seconds.

        Returns:
            List of resolved plaintext strings (URLs, DLL names, API names).
        """
        if not self.project:
            return []

        import claripy

        angr = self._angr
        resolved_strings: List[str] = []
        deadline = time.monotonic() + timeout

        try:
            # Create a blank state at the function entry with symbolic registers
            state = self.project.factory.blank_state(
                addr=start_addr,
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                }
            )

            # Inject symbolic bitvectors into the argument registers.
            # This simulates unknown inputs to decryption routines.
            arch = self.project.arch
            for reg_name in _SYMBOLIC_ARG_REGISTERS.get(arch.name, ()):
                setattr(state.regs, reg_name, claripy.BVS(f"sym_{reg_name}", arch.bits))

            # Configure the simulation manager
            simgr = self.project.factory.simgr(state)

            # Define find/avoid targets
            find_addrs = [end_addr] if end_addr else []

            # Step through the function with bounded execution
            step_count = 0
            while len(simgr.active) > 0 and step_count < MAX_STEPS and time.monotonic() < deadline:
                simgr.step()
                step_count += 1

                # Cap active states to prevent memory explosion
                if len(simgr.active) > MAX_ACTIVE_STATES:
                    simgr.split(from_stash="active", to_stash="overflow", limit=MAX_ACTIVE_STATES)

                # If we have a target end address, check for found states
                if find_addrs:
                    simgr.move(from_stash="active", to_stash="found",
                               filter_func=lambda s: s.addr in find_addrs)
                    if simgr.found:
                        break

            # Harvest strings from terminal states; fall back to whatever is
            # still running if the budget expired first.
            stashes = simgr.stashes
            harvest_states = stashes.get("found") or stashes.get("deadended") or stashes.get("active") or []
            for terminal_state in harvest_states[:MAX_HARVEST_STATES]:
                resolved_strings.extend(
                    self._extract_strings_from_state(terminal_state)
                )

        except Exception as e:
            logger.warning(f"[ConcolicEngine] Exploration failed at 0x{start_addr:08x}: {e}")

        # Deduplicate and return
        return sorted(set(resolved_strings))

    def _extract_strings_from_state(self, state: Any) -> List[str]:
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
                                state.memory.load(seg.min_addr, min(seg.memsize, MEMORY_SCAN_BYTES)),
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


def _child_entry(conn: Any, target: Callable[..., Any], args: Sequence[Any]) -> None:
    """Child-process trampoline: run ``target`` and ship the outcome back."""
    try:
        conn.send((True, target(*args)))
    except BaseException as e:  # report every failure; the parent decides
        conn.send((False, f"{type(e).__name__}: {e}"))
    finally:
        conn.close()


def run_with_hard_timeout(target: Callable[..., Any], args: Sequence[Any],
                          timeout: float) -> Tuple[bool, Any]:
    """
    Run ``target(*args)`` in a child process and kill it if it overruns.

    A thread cannot be cancelled, so a thread-based timeout would leave a
    runaway solver burning CPU (and would block on executor shutdown). A
    spawned process can be terminated outright.

    Returns:
        (True, result) on success; (False, None) on timeout or child failure.
    """
    ctx = multiprocessing.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child_entry, args=(child_conn, target, tuple(args)), daemon=True)
    proc.start()
    child_conn.close()
    deadline = time.monotonic() + timeout
    try:
        # Poll in short slices so a child that dies early (import error,
        # crash) is noticed immediately instead of after the full timeout.
        while not parent_conn.poll(_POLL_INTERVAL_SECONDS):
            if time.monotonic() >= deadline:
                return False, None
            if not proc.is_alive() and not parent_conn.poll(0):
                logger.warning(f"[ConcolicEngine] Worker exited with code {proc.exitcode} before reporting")
                return False, None
        ok, payload = parent_conn.recv()
        if not ok:
            logger.warning(f"[ConcolicEngine] Worker failed: {payload}")
            return False, None
        return True, payload
    except (EOFError, OSError) as e:
        logger.warning(f"[ConcolicEngine] Worker exited unexpectedly: {e}")
        return False, None
    finally:
        if proc.is_alive():
            proc.terminate()
            proc.join(5)
            if proc.is_alive():
                proc.kill()
        proc.join(1)
        parent_conn.close()


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
        timeout:     Maximum seconds of exploration before aborting.

    Returns:
        List of resolved strings, or empty list on timeout/error.
    """
    ok, resolved = run_with_hard_timeout(
        _run_engine,
        (binary_path, start_addr, end_addr, timeout),
        timeout=timeout + STARTUP_GRACE_SECONDS,
    )
    if not ok:
        logger.warning(f"[ConcolicEngine] No result within {timeout}s at 0x{start_addr:08x}")
        return []
    return resolved or []


def _run_engine(binary_path: str, start_addr: int,
                end_addr: Optional[int], timeout: float = TIMEOUT_SECONDS) -> List[str]:
    """Worker function executed in a subprocess."""
    engine = ConcolicEngine(binary_path)
    return engine.explore_function(start_addr, end_addr, timeout=timeout)
