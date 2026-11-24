"""Phase 4 probe: cache correctness, corruption, concurrency, key scoping."""
from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vulnreach.advisories.osv_client import OSVClient  # noqa: E402
from vulnreach.cache.store import CacheStore  # noqa: E402
from vulnreach.callgraph.builder import CallGraphBuilder  # noqa: E402


def row_count(db: Path) -> int:
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]


if __name__ == "__main__":
    tmp = Path(tempfile.mkdtemp(prefix="vr_cache_"))
    try:
        db = tmp / "store.sqlite"
        c = CacheStore(db_path=db)

        print("== basic ==")
        print("miss:", c.get("pkg", "1", "advisory_functions", "A"))
        c.put("pkg", "1", "advisory_functions", {"x": 1}, "A")
        print("hit: ", c.get("pkg", "1", "advisory_functions", "A"))
        print("separate advisory keys coexist:",
              c.get("pkg", "1", "advisory_functions", "A"),
              end=" ")
        c.put("pkg", "1", "advisory_functions", {"x": 2}, "B")
        print(c.get("pkg", "1", "advisory_functions", "B"))
        print("callgraph key ignores advisory id; callgraph:",
              c.get("pkg", "1", "callgraph"))

        print("\n== disabled ==")
        off = CacheStore(db_path=tmp / "off.sqlite", enabled=False)
        off.put("pkg", "1", "callgraph", {"nodes": [], "edges": []})
        print("disabled get:", off.get("pkg", "1", "callgraph"),
              "| db exists:", (tmp / "off.sqlite").exists())

        print("\n== corruption ==")
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE cache SET value = '{not json' WHERE key = 'pkg@1#advisory_functions#A'")
        print("corrupt JSON ->", c.get("pkg", "1", "advisory_functions", "A"))
        print("still safe (not wrong):", c.get("pkg", "1", "advisory_functions", "A") is None)

        print("\n== version invalidation ==")
        c.put("vtest", "1", "callgraph", {"nodes": [], "edges": []})
        print("same version:", c.get("vtest", "1", "callgraph"))
        c2 = CacheStore(db_path=db, analyzer_version="9.9.9")
        print("new version: ", c2.get("vtest", "1", "callgraph"))
        print("row deleted:", c.get("vtest", "1", "callgraph"))

        print("\n== malformed cached graph ==")
        b = CallGraphBuilder(tmp)
        for bad, label in (
            ({"nodes": [{}], "edges": []}, "node missing qualname"),
            ({"nodes": "abc", "edges": []}, "nodes not a list"),
            ({"nodes": [], "edges": [{}]}, "edge missing endpoints"),
        ):
            try:
                b.add_cached_subgraph(CacheStore.deserialize_graph(bad)[0],
                                      CacheStore.deserialize_graph(bad)[1])
                print(f"  {label}: no crash")
            except Exception as exc:
                print(f"  {label}: CRASH:{type(exc).__name__}: {exc}")

        print("\n== silent write failure ==")
        real_connect = sqlite3.connect

        def locked(*a, **k):
            raise sqlite3.OperationalError("database is locked")

        with patch("vulnreach.cache.store.sqlite3.connect", side_effect=locked):
            try:
                c.put("locked", "1", "callgraph", {"nodes": [], "edges": []})
                print("put did not raise (error swallowed)")
            except Exception as exc:
                print("put raised", type(exc).__name__)
        print("entry present:", c.get("locked", "1", "callgraph"))

        print("\n== concurrency ==")
        cdb = tmp / "conc.sqlite"
        conc = CacheStore(db_path=cdb)
        errors: list[str] = []

        def writer(n: int) -> None:
            for i in range(25):
                try:
                    conc.put("t", "1", f"k{n}-{i}", {"i": i})
                except Exception as exc:  # not expected; put swallows sqlite errors
                    errors.append(f"{type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        print("writes attempted: 200; rows stored:", row_count(cdb), "| errors:", errors[:3])
        with sqlite3.connect(cdb) as conn:
            print("journal_mode:", conn.execute("PRAGMA journal_mode").fetchone()[0],
                  "| busy_timeout:", conn.execute("PRAGMA busy_timeout").fetchone()[0])

        print("\n== --no-cache scope ==")
        nocache = CacheStore(db_path=tmp / "nc.sqlite", enabled=False)
        osv = OSVClient(cache_db=tmp / "osv.sqlite")
        print("CacheStore disabled:", nocache.enabled)
        print("OSVClient has enabled flag:", hasattr(osv, "enabled"))
        print("FixCommitResolver uses its own DB keyed by URL, not CacheStore:")
        from vulnreach.advisories.fix_commit import FixCommitResolver
        print("  default:", FixCommitResolver().cache_db)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
