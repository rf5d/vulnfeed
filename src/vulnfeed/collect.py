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
from .sources import kev, nvd


def load_config(path: str | Path) -> dict:
    cfg = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    cfg["vendors"] = [VendorConfig(**v) for v in cfg.get("vendors", [])]
    return cfg


def run(config_path: str, db_path: str, kev_fixture: str | None = None,
        skip_nvd: bool = False) -> dict:
    cfg = load_config(config_path)
    vendors = cfg["vendors"]
    filters = cfg.get("filters", {})
    min_cvss = float(filters.get("min_cvss", 8.6))
    window = int(filters.get("window_days", 60))

    stats = {"new": 0, "changed": 0, "same": 0, "errors": []}

    with db.connect(db_path) as conn:
        # --- CISA KEV ---
        try:
            catalog = kev.load_fixture(kev_fixture) if kev_fixture else kev.fetch()
            items = kev.parse(catalog, vendors)
            for c in items:
                status, changes = db.upsert_cve(conn, c)
                stats[status] += 1
                for field, old, new in changes:
                    print(f"  ~ {c.cve_id}: {field} {old} → {new}")
            db.log_run(conn, "kev", True, len(items))
            print(f"KEV: {len(items)} записей по нашим вендорам")
        except Exception as exc:  # источник упал — прогон продолжается
            db.log_run(conn, "kev", False, 0, str(exc))
            stats["errors"].append(f"kev: {exc}")
            print(f"KEV: ОШИБКА {exc}", file=sys.stderr)

        # --- NVD ---
        if not skip_nvd:
            try:
                items = nvd.collect(vendors, window, min_cvss)
                for c in items:
                    status, changes = db.upsert_cve(conn, c)
                    stats[status] += 1
                    for field, old, new in changes:
                        print(f"  ~ {c.cve_id}: {field} {old} → {new}")
                db.log_run(conn, "nvd", True, len(items))
                print(f"NVD: {len(items)} записей выше порога {min_cvss}")
            except Exception as exc:
                db.log_run(conn, "nvd", False, 0, str(exc))
                stats["errors"].append(f"nvd: {exc}")
                print(f"NVD: ОШИБКА {exc}", file=sys.stderr)

    return stats


def main() -> int:
    ap = argparse.ArgumentParser(prog="vulnfeed-collect")
    ap.add_argument("--config", default="config.toml")
    ap.add_argument("--db", default="data/tracker.db")
    ap.add_argument("--kev-fixture", help="локальный JSON вместо запроса к CISA")
    ap.add_argument("--skip-nvd", action="store_true")
    args = ap.parse_args()

    stats = run(args.config, args.db, args.kev_fixture, args.skip_nvd)
    print(f"\nитог: новых {stats['new']}, изменилось {stats['changed']}, "
          f"без изменений {stats['same']}")
    if stats["errors"]:
        print("источники с ошибками: " + "; ".join(stats["errors"]), file=sys.stderr)
    # Ошибка источника не валит прогон: часть данных лучше, чем ничего.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
