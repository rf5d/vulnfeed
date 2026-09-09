"""Smoke на ядре: дедупликация, история изменений, фильтр вендоров.

Сеть не нужна — всё на фикстурах.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnfeed import db
from vulnfeed.collect import load_config
from vulnfeed.models import Cve, VendorItem
from vulnfeed.sources import kev

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


@pytest.fixture
def vendors():
    return load_config(ROOT / "config.toml")["vendors"]


def test_kev_filters_foreign_vendors(vendors):
    catalog = kev.load_fixture(FIX / "kev_sample.json")
    found = kev.parse(catalog, vendors)
    ids = {c.cve_id for c in found}
    assert "CVE-2026-83548" in ids
    assert "CVE-2026-00000" not in ids, "чужой вендор просочился сквозь фильтр"
    assert len(found) == 3


def test_kev_maps_fields(vendors):
    catalog = kev.load_fixture(FIX / "kev_sample.json")
    sonic = next(c for c in kev.parse(catalog, vendors) if c.cve_id == "CVE-2026-83548")
    assert sonic.vendor == "SonicWall"
    assert sonic.in_kev == 1
    assert sonic.kev_date == "2026-09-02"
    assert sonic.ransomware == 1
    assert sonic.url.endswith("CVE-2026-83548")


def test_second_run_is_idempotent(tmp_path, vendors):
    """Тот же каталог дважды не должен плодить дубли и события."""
    path = tmp_path / "t.db"
    catalog = kev.load_fixture(FIX / "kev_sample.json")
    items = kev.parse(catalog, vendors)

    with db.connect(path) as conn:
        first = [db.upsert_cve(conn, c)[0] for c in items]
    assert set(first) == {"new"}

    with db.connect(path) as conn:
        second = [db.upsert_cve(conn, c)[0] for c in items]
        rows = conn.execute("SELECT COUNT(*) c FROM cve").fetchone()["c"]
        events = conn.execute("SELECT COUNT(*) c FROM cve_event").fetchone()["c"]

    assert set(second) == {"same"}
    assert rows == 3, "повторный прогон задвоил записи"
    assert events == 0, "повторный прогон записал события на пустом месте"


def test_changes_land_in_history(tmp_path, vendors):
    path = tmp_path / "t.db"
    v1 = kev.parse(kev.load_fixture(FIX / "kev_sample.json"), vendors)
    v2 = kev.parse(kev.load_fixture(FIX / "kev_sample_v2.json"), vendors)

    with db.connect(path) as conn:
        for c in v1:
            db.upsert_cve(conn, c)

    with db.connect(path) as conn:
        statuses = {c.cve_id: db.upsert_cve(conn, c)[0] for c in v2}
        events = conn.execute(
            "SELECT cve_id, field, old_value, new_value FROM cve_event ORDER BY field"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) c FROM cve").fetchone()["c"]

    assert statuses["CVE-2026-77550"] == "new"
    assert statuses["CVE-2026-20349"] == "changed"
    assert statuses["CVE-2021-33044"] == "same"
    assert total == 4

    fields = {(e["cve_id"], e["field"]) for e in events}
    assert ("CVE-2026-20349", "description") in fields
    assert ("CVE-2026-20349", "ransomware") in fields


def test_vendor_item_key_survives_title_change(tmp_path):
    """Вендор переписал заголовок — запись не должна задвоиться."""
    path = tmp_path / "t.db"
    a = VendorItem(vendor="MikroTik", kind="fw", title="RouterOS 7.24.2",
                   url="https://example.invalid/a")
    b = VendorItem(vendor="MikroTik", kind="fw", title="RouterOS 7.24.2 (stable)",
                   url="https://example.invalid/a/")

    with db.connect(path) as conn:
        assert db.upsert_vendor_item(conn, a) == "new"
        assert db.upsert_vendor_item(conn, b) == "same"
        rows = conn.execute("SELECT title FROM vendor_item").fetchall()

    assert len(rows) == 1
    assert rows[0]["title"] == "RouterOS 7.24.2 (stable)", "заголовок должен обновиться"


def test_cvss_null_does_not_erase_existing(tmp_path):
    """KEV не знает CVSS. Его запись не должна затирать оценку из NVD."""
    path = tmp_path / "t.db"
    with db.connect(path) as conn:
        db.upsert_cve(conn, Cve(cve_id="CVE-2026-1", vendor="X", cvss=9.8, cvss_version="3.1"))
        db.upsert_cve(conn, Cve(cve_id="CVE-2026-1", vendor="X", in_kev=1, kev_date="2026-09-01"))
        row = conn.execute("SELECT cvss, in_kev FROM cve WHERE cve_id='CVE-2026-1'").fetchone()

    assert row["cvss"] == 9.8, "запись из KEV затёрла оценку CVSS"
    assert row["in_kev"] == 1
