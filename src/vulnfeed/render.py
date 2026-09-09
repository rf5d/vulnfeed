"""Генератор статики: база → docs/index.html.

Никакого рантайма на отдаче. GitHub Pages раздаёт /docs как есть.

Записи делятся на две секции. Свежее за окно — сверху, потому что это
новости. Всё остальное — свёрнутый полный список: KEV не про новизну,
а про то, что эксплуатируется прямо сейчас, и старая дыра в железе,
которое годами стоит у клиента, из этого списка выпадать не должна.
"""

from __future__ import annotations

import argparse
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import db


def _day(value: str | None) -> str | None:
    """Привести дату любого из наших форматов к YYYY-MM-DD."""
    return value[:10] if value else None


def is_fresh(row: dict, cutoff: str) -> bool:
    """Свежая, если попала в KEV или опубликована в NVD после границы окна."""
    days = [d for d in (_day(row.get("kev_date")), _day(row.get("published"))) if d]
    return any(d >= cutoff for d in days)


def collect_context(db_path: str, fresh_days: int = 60, limit: int = 1000) -> dict:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=fresh_days)).strftime("%Y-%m-%d")

    with db.connect(db_path) as conn:
        rows = [dict(r) for r in conn.execute(
            """SELECT * FROM cve
               ORDER BY in_kev DESC, COALESCE(cvss, 0) DESC, first_seen DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()]
        events = [dict(r) for r in conn.execute(
            """SELECT e.*, c.vendor FROM cve_event e
               JOIN cve c ON c.cve_id = e.cve_id
               ORDER BY e.at DESC LIMIT 40"""
        ).fetchall()]
        items = [dict(r) for r in conn.execute(
            "SELECT * FROM vendor_item ORDER BY COALESCE(date, first_seen) DESC LIMIT ?",
            (limit,),
        ).fetchall()]
        runs = [dict(r) for r in conn.execute(
            "SELECT * FROM run ORDER BY at DESC LIMIT 12"
        ).fetchall()]

    fresh = [r for r in rows if is_fresh(r, cutoff)]
    rest = [r for r in rows if not is_fresh(r, cutoff)]

    # Счётчики для кнопок-фильтров: считаем по всем записям, не только свежим.
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["vendor"]] = counts.get(r["vendor"], 0) + 1
    vendors = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    return {
        "fresh": fresh,
        "rest": rest,
        "total": len(rows),
        "kev_count": sum(1 for r in rows if r["in_kev"]),
        "fresh_kev": sum(1 for r in fresh if r["in_kev"]),
        "vendors": vendors,
        "events": events,
        "items": items,
        "runs": runs,
        "fresh_days": fresh_days,
        "cutoff": cutoff,
        "generated": datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC"),
    }


def render(db_path: str, out: str, templates: str = "templates",
           fresh_days: int = 60) -> Path:
    env = Environment(
        loader=FileSystemLoader(templates),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    ctx = collect_context(db_path, fresh_days=fresh_days)
    html = env.get_template("index.html.j2").render(**ctx)
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(prog="vulnfeed-render")
    ap.add_argument("--db", default="data/tracker.db")
    ap.add_argument("--out", default="docs/index.html")
    ap.add_argument("--templates", default="templates")
    ap.add_argument("--config", default="config.toml")
    args = ap.parse_args()

    fresh_days = 60
    cfg_path = Path(args.config)
    if cfg_path.exists():
        cfg = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
        fresh_days = int(cfg.get("filters", {}).get("fresh_days", 60))

    path = render(args.db, args.out, args.templates, fresh_days)
    print(f"собрано: {path} ({path.stat().st_size} байт), окно свежего {fresh_days} дн.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
