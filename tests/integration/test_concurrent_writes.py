"""P0-09: Concurrent write serialization tests.

Verify that concurrent writers to the same repo are serialized by
advisory locks (fcntl.LOCK_EX) and that no data corruption occurs.
"""

import threading
import time

import pytest

from codesight_mcp.parser import Symbol
from codesight_mcp.storage import IndexStore


def _make_symbol(name: str, file_name: str = "test.py") -> tuple[Symbol, str]:
    """Create a Symbol and its source string for testing."""
    src = f"def {name}():\n    return '{name}'\n"
    sym = Symbol(
        id=f"{file_name}::{name}#function",
        file=file_name,
        name=name,
        qualified_name=name,
        kind="function",
        language="python",
        signature=f"def {name}():",
        byte_offset=0,
        byte_length=len(src),
    )
    return sym, src


class TestConcurrentWriteSerialization:
    """Spawn multiple threads that each call save_index to the same repo.

    Since save_index acquires an exclusive advisory lock, writers are
    serialized. The final index should contain the symbols from the
    LAST writer to complete.
    """

    def test_concurrent_writers_produce_valid_index(self, tmp_path):
        """4 threads write different symbols to the same repo concurrently.
        The final index must be loadable and contain exactly 1 symbol
        (from whichever thread wrote last)."""
        store = IndexStore(base_path=str(tmp_path))
        errors: list[Exception] = []
        write_order: list[str] = []
        lock = threading.Lock()

        def writer(thread_id: str):
            try:
                sym, src = _make_symbol(f"func_{thread_id}")
                store.save_index(
                    owner="local",
                    name="shared",
                    source_files=["test.py"],
                    symbols=[sym],
                    raw_files={"test.py": src},
                    languages={"python": 1},
                )
                with lock:
                    write_order.append(thread_id)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=writer, args=(f"t{i}",)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Writer threads raised exceptions: {errors}"
        assert len(write_order) == 4, f"Not all writers completed: {write_order}"

        # The final index must be loadable
        idx = store.load_index("local", "shared")
        assert idx is not None
        assert len(idx.symbols) == 1

        # The symbol should be from the last writer (serialized by lock)
        last_writer = write_order[-1]
        assert idx.symbols[0]["name"] == f"func_{last_writer}"

    def test_index_always_loadable_after_concurrent_writes(self, tmp_path):
        """After concurrent writes, the index must always be loadable
        (not corrupted)."""
        store = IndexStore(base_path=str(tmp_path))
        errors: list[Exception] = []

        def writer(thread_id: int):
            try:
                sym, src = _make_symbol(f"func_{thread_id}")
                store.save_index(
                    owner="local",
                    name="integrity",
                    source_files=["test.py"],
                    symbols=[sym],
                    raw_files={"test.py": src},
                    languages={"python": 1},
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Writer threads raised exceptions: {errors}"

        # Index must be loadable (not corrupt)
        idx = store.load_index("local", "integrity")
        assert idx is not None
        assert idx.owner == "local"
        assert idx.name == "integrity"
        assert len(idx.symbols) == 1
        assert idx.symbols[0]["kind"] == "function"

    def test_concurrent_writes_to_different_repos_independent(self, tmp_path):
        """Writers to different repos should not interfere with each other."""
        store = IndexStore(base_path=str(tmp_path))
        errors: list[Exception] = []

        def writer(repo_name: str, sym_name: str):
            try:
                sym, src = _make_symbol(sym_name)
                store.save_index(
                    owner="local",
                    name=repo_name,
                    source_files=["test.py"],
                    symbols=[sym],
                    raw_files={"test.py": src},
                    languages={"python": 1},
                )
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=writer, args=(f"repo{i}", f"func{i}"))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Writer threads raised exceptions: {errors}"

        # Each repo should have its own independent index
        for i in range(4):
            idx = store.load_index("local", f"repo{i}")
            assert idx is not None, f"repo{i} index not found"
            assert len(idx.symbols) == 1
            assert idx.symbols[0]["name"] == f"func{i}"


class TestLockContentionTimeout:
    """Verify lock contention doesn't cause deadlocks."""

    def test_no_deadlock_under_contention(self, tmp_path):
        """Multiple threads contending for the same lock all complete
        within a reasonable timeout (no deadlock)."""
        store = IndexStore(base_path=str(tmp_path))
        completed = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def slow_writer(thread_id: int):
            try:
                sym, src = _make_symbol(f"slow_{thread_id}")
                store.save_index(
                    owner="local",
                    name="contended",
                    source_files=["test.py"],
                    symbols=[sym],
                    raw_files={"test.py": src},
                    languages={"python": 1},
                )
                with lock:
                    completed.append(thread_id)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=slow_writer, args=(i,)) for i in range(8)]
        start = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        elapsed = time.monotonic() - start

        # All threads must have completed (no hangs/deadlocks)
        alive_threads = [t for t in threads if t.is_alive()]
        assert not alive_threads, f"Threads still alive after 60s (deadlock): {alive_threads}"

        assert not errors, f"Writer threads raised exceptions: {errors}"
        assert len(completed) == 8, f"Only {len(completed)}/8 threads completed"
        # Sanity: should finish well under 60 seconds
        assert elapsed < 60, f"Took {elapsed:.1f}s -- possible deadlock"

    def test_read_after_concurrent_write_is_consistent(self, tmp_path):
        """A read immediately after concurrent writes returns a valid,
        internally consistent index."""
        store = IndexStore(base_path=str(tmp_path))
        errors: list[Exception] = []

        def writer(thread_id: int):
            try:
                sym, src = _make_symbol(f"w{thread_id}")
                store.save_index(
                    owner="local",
                    name="readtest",
                    source_files=["test.py"],
                    symbols=[sym],
                    raw_files={"test.py": src},
                    languages={"python": 1},
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors

        # Read and verify internal consistency
        idx = store.load_index("local", "readtest")
        assert idx is not None
        assert idx.repo == "local/readtest"
        assert idx.owner == "local"
        assert idx.name == "readtest"
        assert len(idx.symbols) == 1
        assert len(idx.source_files) == 1
        assert idx.source_files[0] == "test.py"

        # The symbol must match the source file it references
        sym = idx.symbols[0]
        assert sym["file"] in idx.source_files
        assert sym["kind"] == "function"
        assert sym["language"] == "python"


class TestConcurrentReadWrite:
    """GAP-3: Concurrent reads during writes must not crash or return partial data."""

    def test_read_during_write_never_crashes(self, tmp_path):
        """Spawn writers and readers concurrently. Readers must never crash
        or return partially-written data."""
        store = IndexStore(base_path=str(tmp_path))

        # Seed initial index
        sym, src = _make_symbol("initial")
        store.save_index(
            owner="local", name="rw",
            source_files=["test.py"],
            symbols=[sym],
            raw_files={"test.py": src},
            languages={"python": 1},
        )

        write_errors: list[Exception] = []
        read_errors: list[Exception] = []
        read_results: list = []
        stop_flag = threading.Event()
        lock = threading.Lock()

        def writer(thread_id: int):
            try:
                for i in range(5):
                    s, content = _make_symbol(f"w{thread_id}_iter{i}")
                    store.save_index(
                        owner="local", name="rw",
                        source_files=["test.py"],
                        symbols=[s],
                        raw_files={"test.py": content},
                        languages={"python": 1},
                    )
            except Exception as exc:
                with lock:
                    write_errors.append(exc)
            finally:
                stop_flag.set()

        def reader():
            try:
                while not stop_flag.is_set():
                    idx = store.load_index("local", "rw")
                    if idx is not None:
                        # Must be internally consistent
                        assert isinstance(idx.symbols, list)
                        assert len(idx.symbols) >= 0
                        assert idx.owner == "local"
                        assert idx.name == "rw"
                        with lock:
                            read_results.append(len(idx.symbols))
            except Exception as exc:
                with lock:
                    read_errors.append(exc)

        writers = [threading.Thread(target=writer, args=(i,)) for i in range(2)]
        readers = [threading.Thread(target=reader) for _ in range(3)]

        for t in readers + writers:
            t.start()
        for t in writers:
            t.join(timeout=30)
        stop_flag.set()
        for t in readers:
            t.join(timeout=5)

        assert not write_errors, f"Writer errors: {write_errors}"
        assert not read_errors, f"Reader errors: {read_errors}"
        assert len(read_results) > 0, "Readers should have completed at least one read"
