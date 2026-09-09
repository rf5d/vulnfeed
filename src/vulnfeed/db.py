"""Хранилище трекера: SQLite + upsert с историей изменений.

Ядро проекта. Дашборд хранил снимок — здесь запись живёт долго и меняет
состояние, поэтому каждое изменение отслеживаемого поля пишется в cve_event.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .models import Cve, VendorItem

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS cve (
    cve_id        TEXT PRIMARY KEY,
    vendor        TEXT NOT NULL,
    product       TEXT,
    title         TEXT,
    description   TEXT,
    cvss          REAL,
    cvss_version  TEXT,
    in_kev        INTEGER NOT NULL DEFAULT 0,
    kev_date      TEXT,
    ransomware    INTEGER NOT NULL DEFAULT 0,
    published     TEXT,
    last_modified TEXT,
    url           TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_event (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id    TEXT NOT NULL REFERENCES cve(cve_id),
    at        TEXT NOT NULL,
    field     TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_cve ON cve_event(cve_id, at DESC);

CREATE TABLE IF NOT EXISTS vendor_item (
    item_key   TEXT PRIMARY KEY,
    vendor     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    date       TEXT,
    title      TEXT NOT NULL,
    body       TEXT,
    url        TEXT NOT NULL,
    hot        INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vendor_date ON vendor_item(date DESC);

CREATE TABLE IF NOT EXISTS run (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     TEXT NOT NULL,
    source TEXT NOT NULL,
    ok     INTEGER NOT NULL,
    items  INTEGER NOT NULL DEFAULT 0,
    error  TEXT
);
"""

# Поля, изменение которых считается событием и попадает в историю.
# cvss тут намеренно есть: NVD пересматривает оценки, и это стоит видеть.
TRACKED = ("cvss", "in_kev", "kev_date", "ransomware", "description", "last_modified")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def item_key(vendor: str, url: str) -> str:
    """Ключ дедупликации вендорской записи.

    По (вендор, URL), а не по заголовку: заголовок вендор правит молча,
    и запись задваивалась бы при каждом переименовании.
    """
    raw = f"{vendor.strip().lower()}|{url.strip().rstrip('/').lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@contextmanager
def connect(path: str | Path) -> Iterator[sqlite3.Connection]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_cve(conn: sqlite3.Connection, cve: Cve) -> tuple[str, list[tuple[str, str, str]]]:
    """Вставить или обновить CVE. Возвращает (статус, список изменений).

    Статус: "new" | "changed" | "same".
    """
    ts = now()
    row = conn.execute("SELECT * FROM cve WHERE cve_id = ?", (cve.cve_id,)).fetchone()
    data = asdict(cve)

    if row is None:
        conn.execute(
            """INSERT INTO cve (cve_id, vendor, product, title, description, cvss,
                                cvss_version, in_kev, kev_date, ransomware, published,
                                last_modified, url, first_seen, last_seen)
               VALUES (:cve_id, :vendor, :product, :title, :description, :cvss,
                       :cvss_version, :in_kev, :kev_date, :ransomware, :published,
                       :last_modified, :url, :ts, :ts)""",
            {**data, "ts": ts},
        )
        return "new", []

    changes: list[tuple[str, str, str]] = []
    for field in TRACKED:
        old, new = row[field], data[field]
        if new is None or str(old) == str(new):
            continue
        changes.append((field, str(old), str(new)))
        conn.execute(
            "INSERT INTO cve_event (cve_id, at, field, old_value, new_value) VALUES (?,?,?,?,?)",
            (cve.cve_id, ts, field, str(old), str(new)),
        )

    # Поля, которые просто освежаем без истории.
    conn.execute(
        """UPDATE cve SET vendor=:vendor, product=:product, title=:title,
                          description=COALESCE(:description, description),
                          cvss=COALESCE(:cvss, cvss), cvss_version=:cvss_version,
                          in_kev=:in_kev, kev_date=COALESCE(:kev_date, kev_date),
                          ransomware=:ransomware,
                          last_modified=COALESCE(:last_modified, last_modified),
                          url=:url, last_seen=:ts
           WHERE cve_id=:cve_id""",
        {**data, "ts": ts},
    )
    return ("changed" if changes else "same"), changes


def upsert_vendor_item(conn: sqlite3.Connection, item: VendorItem) -> str:
    ts = now()
    key = item_key(item.vendor, item.url)
    row = conn.execute("SELECT item_key FROM vendor_item WHERE item_key = ?", (key,)).fetchone()
    if row is None:
        conn.execute(
            """INSERT INTO vendor_item (item_key, vendor, kind, date, title, body, url,
                                        hot, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (key, item.vendor, item.kind, item.date, item.title, item.body,
             item.url, int(item.hot), ts, ts),
        )
        return "new"
    conn.execute(
        """UPDATE vendor_item SET kind=?, date=COALESCE(?, date), title=?,
                                  body=COALESCE(?, body), hot=?, last_seen=?
           WHERE item_key=?""",
        (item.kind, item.date, item.title, item.body, int(item.hot), ts, key),
    )
    return "same"


def log_run(conn: sqlite3.Connection, source: str, ok: bool, items: int = 0,
            error: str | None = None) -> None:
    conn.execute(
        "INSERT INTO run (at, source, ok, items, error) VALUES (?,?,?,?,?)",
        (now(), source, int(ok), items, error),
    )
