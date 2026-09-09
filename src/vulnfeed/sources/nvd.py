"""NVD API 2.0 — оценки CVSS и описания.

Без ключа лимит жёсткий (порядка 5 запросов на 30 секунд), с ключом заметно
выше. Ключ бесплатный, кладётся в NVD_API_KEY. Между страницами всегда пауза:
NVD банит по частоте, а не по объёму.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Iterable

import httpx

from ..models import Cve, VendorConfig

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 200


def _best_cvss(metrics: dict) -> tuple[float | None, str | None]:
    """Взять оценку по приоритету версий: v4.0 → v3.1 → v3.0 → v2."""
    for key, label in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        score = primary.get("cvssData", {}).get("baseScore")
        if score is not None:
            return float(score), label
    return None, None


def _english(descriptions: list[dict]) -> str | None:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value")
    return None


def search(keyword: str, window_days: int, api_key: str | None = None,
           pause: float = 6.0, timeout: float = 60.0) -> list[dict]:
    """Все CVE по ключевому слову, изменённые за окно. Возвращает сырые записи."""
    api_key = api_key or os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    if api_key:
        pause = 1.0

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=window_days)
    base = {
        "keywordSearch": keyword,
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": PAGE,
    }

    out: list[dict] = []
    offset = 0
    with httpx.Client(timeout=timeout, headers=headers) as client:
        while True:
            resp = client.get(API, params={**base, "startIndex": offset})
            resp.raise_for_status()
            body = resp.json()
            batch = body.get("vulnerabilities", [])
            out.extend(batch)
            total = body.get("totalResults", 0)
            offset += PAGE
            if offset >= total or not batch:
                break
            time.sleep(pause)
    return out


def parse(raw: list[dict], vendor: VendorConfig, min_cvss: float) -> list[Cve]:
    """Отфильтровать по порогу CVSS и собрать модели."""
    out: list[Cve] = []
    for entry in raw:
        c = entry.get("cve", {})
        if c.get("vulnStatus") == "Rejected":
            continue
        score, version = _best_cvss(c.get("metrics", {}))
        if score is None or score < min_cvss:
            continue
        out.append(
            Cve(
                cve_id=c["id"],
                vendor=vendor.name,
                description=_english(c.get("descriptions", [])),
                cvss=score,
                cvss_version=version,
                published=c.get("published"),
                last_modified=c.get("lastModified"),
            )
        )
    return out


def collect(vendors: Iterable[VendorConfig], window_days: int, min_cvss: float,
            api_key: str | None = None, pause_between: float = 7.0) -> list[Cve]:
    """Пройти по вендорам с паузой между ними.

    Пауза именно здесь, а не только внутри search(): у большинства вендоров
    результат укладывается в одну страницу, внутристраничная задержка тогда
    не срабатывает вообще, и десять вендоров подряд улетают в NVD одной
    очередью — это ровно тот случай, за который он отдаёт 403.
    """
    api_key = api_key or os.environ.get("NVD_API_KEY")
    if api_key:
        pause_between = 1.0

    found: list[Cve] = []
    first = True
    for v in vendors:
        if not v.nvd_keyword:
            continue
        if not first:
            time.sleep(pause_between)
        first = False
        raw = search(v.nvd_keyword, window_days, api_key=api_key)
        found.extend(parse(raw, v, min_cvss))
    return found
