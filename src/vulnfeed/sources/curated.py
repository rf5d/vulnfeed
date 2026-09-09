"""Курируемая лента: vendor_feed.toml.

Нужна потому, что EOL и EOS у большинства вендоров машиной не берутся —
RUCKUS держит бюллетени за логином, Dahua и пресс-раздел TP-Link отвечают
403. Записи добавляются руками, но по тем же правилам, что и автоматические:
обязательный URL, дата, тип. История правок остаётся в git.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from ..models import VendorItem

VALID_KINDS = {"eol", "new", "fw"}


def load(path: str | Path) -> list[VendorItem]:
    p = Path(path)
    if not p.exists():
        return []

    raw = tomllib.loads(p.read_text(encoding="utf-8"))
    out: list[VendorItem] = []
    for i, row in enumerate(raw.get("item", []), 1):
        missing = [f for f in ("vendor", "kind", "title", "url") if not row.get(f)]
        if missing:
            raise ValueError(f"{p}: запись #{i} без обязательных полей: {', '.join(missing)}")
        if row["kind"] not in VALID_KINDS:
            raise ValueError(
                f"{p}: запись #{i} — неизвестный kind {row['kind']!r}, "
                f"допустимы {', '.join(sorted(VALID_KINDS))}"
            )
        out.append(VendorItem(
            vendor=row["vendor"],
            kind=row["kind"],
            title=row["title"],
            url=row["url"],
            date=row.get("date"),
            body=row.get("body"),
            hot=bool(row.get("hot", False)),
        ))
    return out
