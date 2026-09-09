"""Генератор статики: база → docs/index.html.

Никакого рантайма на отдаче. GitHub Pages раздаёт /docs как есть.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import db


def collect_context(db_path: str, limit: int = 200) -> dict:
    with db.connect(db_path) as conn:
        cves = conn.execute(
            """SELECT * FROM cve
               ORDER BY in_kev DESC, COALESCE(cvss, 0) DESC, first_seen DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        events = conn.execute(
            """SELECT e.*, c.vendor FROM cve_event e
               JOIN cve c ON c.cve_id = e.cve_id
               ORDER BY e.at DESC LIMIT 40"""
        ).fetchall()
        items = conn.execute(
            "SELECT * FROM vendor_item ORDER BY COALESCE(date, first_seen) DESC LIMIT ?",
            (limit,),
        ).fetchall()
        runs = conn.execute(
            "SELECT * FROM run ORDER BY at DESC LIMIT 12"
        ).fetchall()

        return {
            "cves": [dict(r) for r in cves],
            "events": [dict(r) for r in events],
            "items": [dict(r) for r in items],
            "runs": [dict(r) for r in runs],
            "kev_count": sum(1 for r in cves if r["in_kev"]),
            "generated": datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC"),
        }


def render(db_path: str, out: str, templates: str = "templates") -> Path:
    env = Environment(
        loader=FileSystemLoader(templates),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    html = env.get_template("index.html.j2").render(**collect_context(db_path))
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(prog="vulnfeed-render")
    ap.add_argument("--db", default="data/tracker.db")
    ap.add_argument("--out", default="docs/index.html")
    ap.add_argument("--templates", default="templates")
    args = ap.parse_args()
    path = render(args.db, args.out, args.templates)
    print(f"собрано: {path} ({path.stat().st_size} байт)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
