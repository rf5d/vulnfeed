"""CISA KEV — готовый JSON-каталог, качается целиком и фильтруется локально.

Самый надёжный источник в проекте: один файл, без ключей и пагинации.
Попадание в KEV means подтверждённая эксплуатация — это и есть главный
сигнал отбора, важнее любой оценки CVSS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import httpx

from ..models import Cve, VendorConfig

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch(url: str = KEV_URL, timeout: float = 60.0) -> dict:
    resp = httpx.get(url, timeout=timeout, follow_redirects=True)
    resp.raise_for_status()
    return resp.json()


def load_fixture(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _matches(vendor_project: str, product: str, cfg: VendorConfig) -> bool:
    haystack = f"{vendor_project} {product}".lower()
    return any(m.lower() in haystack for m in cfg.kev_match)


def parse(catalog: dict, vendors: Iterable[VendorConfig]) -> list[Cve]:
    """Отобрать из каталога записи по нашим вендорам."""
    vendors = list(vendors)
    out: list[Cve] = []
    for v in catalog.get("vulnerabilities", []):
        vendor_project = v.get("vendorProject", "")
        product = v.get("product", "")
        cfg = next((c for c in vendors if _matches(vendor_project, product, c)), None)
        if cfg is None:
            continue
        out.append(
            Cve(
                cve_id=v["cveID"],
                vendor=cfg.name,
                product=product or None,
                title=v.get("vulnerabilityName") or None,
                description=v.get("shortDescription") or None,
                in_kev=1,
                kev_date=v.get("dateAdded") or None,
                ransomware=1 if v.get("knownRansomwareCampaignUse") == "Known" else 0,
            )
        )
    return out
