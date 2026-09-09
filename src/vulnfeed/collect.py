"""Оркестратор прогона: источники → база → статика.

Каждый источник изолирован: падение одного не роняет прогон, ошибка пишется
в таблицу run. Пустой результат по источнику — это факт, а не повод
подставить старые данные.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

from . import db
from .models import VendorConfig
from .sources import curated, kev, nvd, vendors as vendor_sources


def load_config(path: str | Path) -> dict:
    cfg = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    cfg["vendors"] = [VendorConfig(**v) for v in cfg.get("vendors", [])]
    return cfg


def _store_cves(conn, items, stats, label):
    for c in items:
        status, changes = db.upsert_cve(conn, c)
        stats[status] += 1
        for field, old, new in changes:
            print(f"  ~ {c.cve_id}: {field} {old} → {new}")
    db.log_run(conn, label, True, len(items))


def _store_items(conn, items, stats, label):
    fresh = 0
    for it in items:
        if db.upsert_vendor_item(conn, it) == "new":
            fresh += 1
    stats["items_new"] += fresh
    db.log_run(conn, label, True, len(items))
    print(f"{label}: {len(items)} записей ({fresh} новых)")


def run(config_path: str, db_path: str, kev_fixture: str | None = None,
        skip_nvd: bool = False, feed_path: str = "vendor_feed.toml",
        skip_vendors: bool = False) -> dict:
    cfg = load_config(config_path)
    vendor_list = cfg["vendors"]
    filters = cfg.get("filters", {})
    min_cvss = float(filters.get("min_cvss", 8.6))
    window = int(filters.get("window_days", 60))

    stats = {"new": 0, "changed": 0, "same": 0, "items_new": 0, "errors": []}

    with db.connect(db_path) as conn:
        # --- CISA KEV ---
        try:
            catalog = kev.load_fixture(kev_fixture) if kev_fixture else kev.fetch()
            items = kev.parse(catalog, vendor_list)
            _store_cves(conn, items, stats, "kev")
            print(f"KEV: {len(items)} записей по нашим вендорам")
        except Exception as exc:
            db.log_run(conn, "kev", False, 0, str(exc))
            stats["errors"].append(f"kev: {exc}")
            print(f"KEV: ОШИБКА {exc}", file=sys.stderr)

        # --- NVD ---
        if not skip_nvd:
            try:
                items = nvd.collect(vendor_list, window, min_cvss)
                _store_cves(conn, items, stats, "nvd")
                print(f"NVD: {len(items)} записей выше порога {min_cvss}")
            except Exception as exc:
                db.log_run(conn, "nvd", False, 0, str(exc))
                stats["errors"].append(f"nvd: {exc}")
                print(f"NVD: ОШИБКА {exc}", file=sys.stderr)

        # --- курируемая лента: то, что за логином и под 403 ---
        try:
            items = curated.load(feed_path)
            _store_items(conn, items, stats, "curated")
        except Exception as exc:
            db.log_run(conn, "curated", False, 0, str(exc))
            stats["errors"].append(f"curated: {exc}")
            print(f"curated: ОШИБКА {exc}", file=sys.stderr)

        # --- автоматические вендорские источники ---
        if not skip_vendors:
            # источникам полезно знать, что уже собрано: Ubiquiti по этому
            # списку не перезапрашивает статьи, которые уже в базе
            known = {r["url"] for r in conn.execute("SELECT url FROM vendor_item")}
            for label, fn in vendor_sources.SOURCES.items():
                try:
                    items = fn(known)
                    _store_items(conn, items, stats, f"vendor:{label}")
                    if not items:
                        print(f"  ! {label}: ноль записей — вероятно, изменилась вёрстка",
                              file=sys.stderr)
                except Exception as exc:
                    db.log_run(conn, f"vendor:{label}", False, 0, str(exc))
                    stats["errors"].append(f"vendor:{label}: {exc}")
                    print(f"vendor:{label}: ОШИБКА {exc}", file=sys.stderr)

    return stats


def main() -> int:
    ap = argparse.ArgumentParser(prog="vulnfeed-collect")
    ap.add_argument("--config", default="config.toml")
    ap.add_argument("--db", default="data/tracker.db")
    ap.add_argument("--feed", default="vendor_feed.toml")
    ap.add_argument("--kev-fixture", help="локальный JSON вместо запроса к CISA")
    ap.add_argument("--skip-nvd", action="store_true")
    ap.add_argument("--skip-vendors", action="store_true",
                    help="не ходить на сайты вендоров (только курируемая лента)")
    args = ap.parse_args()

    stats = run(args.config, args.db, args.kev_fixture, args.skip_nvd,
                args.feed, args.skip_vendors)
    print(f"\nитог CVE: новых {stats['new']}, изменилось {stats['changed']}, "
          f"без изменений {stats['same']}; новых записей в ленте {stats['items_new']}")
    if stats["errors"]:
        print("источники с ошибками: " + "; ".join(stats["errors"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
