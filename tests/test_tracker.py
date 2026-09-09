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


def test_fresh_split_uses_both_dates():
    from vulnfeed.render import is_fresh
    cutoff = "2026-07-11"
    assert is_fresh({"kev_date": "2026-09-02", "published": None}, cutoff)
    assert is_fresh({"kev_date": None, "published": "2026-08-15T10:00:00.000"}, cutoff)
    # старая запись в KEV, но переопубликована недавно — считаем свежей
    assert is_fresh({"kev_date": "2021-11-03", "published": "2026-08-01T00:00:00.000"}, cutoff)
    assert not is_fresh({"kev_date": "2021-11-03", "published": "2021-10-01T00:00:00.000"}, cutoff)
    assert not is_fresh({"kev_date": None, "published": None}, cutoff)


def test_context_splits_and_counts(tmp_path):
    from vulnfeed.render import collect_context
    from datetime import datetime, timedelta, timezone

    today = datetime.now(timezone.utc)
    recent = (today - timedelta(days=5)).strftime("%Y-%m-%d")
    ancient = (today - timedelta(days=900)).strftime("%Y-%m-%d")

    path = tmp_path / "t.db"
    with db.connect(path) as conn:
        db.upsert_cve(conn, Cve(cve_id="CVE-2026-A", vendor="Dahua",
                                in_kev=1, kev_date=recent, cvss=9.8))
        db.upsert_cve(conn, Cve(cve_id="CVE-2021-B", vendor="Dahua",
                                in_kev=1, kev_date=ancient, cvss=9.8))
        db.upsert_cve(conn, Cve(cve_id="CVE-2021-C", vendor="Cisco",
                                in_kev=1, kev_date=ancient, cvss=8.6))

    ctx = collect_context(str(path), fresh_days=60)
    assert [c["cve_id"] for c in ctx["fresh"]] == ["CVE-2026-A"]
    assert {c["cve_id"] for c in ctx["rest"]} == {"CVE-2021-B", "CVE-2021-C"}
    assert ctx["total"] == 3 and ctx["kev_count"] == 3 and ctx["fresh_kev"] == 1
    # счётчики фильтров считают по всем записям, отсортированы по убыванию
    assert ctx["vendors"] == [("Dahua", 2), ("Cisco", 1)]
