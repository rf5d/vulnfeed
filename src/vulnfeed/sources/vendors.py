"""Автоматические вендорские источники.

Работают только там, где вендор отдаёт страницу машине. Проверено:
  MikroTik changelogs — версии RouterOS с датами, разбирается надёжно;
  blog.ui.com — RSS нет, но список постов с датами разбирается.
Не работают и подключены быть не могут: форум MikroTik (robots.txt),
omadanetworks.com/press (403), RUCKUS (за логином), Dahua (403 + robots).
Для них есть vendor_feed.toml.

Парсеры HTML хрупкие по своей природе: вендор меняет вёрстку — источник
молча пустеет. Поэтому каждый возвращает список и не бросает исключение
на пустом результате, а вызывающий пишет в таблицу run, сколько пришло.
Ноль записей в логе — сигнал, что пора смотреть разметку.
"""

from __future__ import annotations

import re
from html import unescape

import httpx

from ..models import VendorItem

MIKROTIK_CHANGELOGS = "https://mikrotik.com/download/changelogs"
UI_BLOG = "https://blog.ui.com/"

UA = {"User-Agent": "vulnfeed/0.1 (personal vendor tracker)"}


def _text(url: str, timeout: float = 45.0) -> str:
    resp = httpx.get(url, timeout=timeout, headers=UA, follow_redirects=True)
    resp.raise_for_status()
    return resp.text


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", s))).strip()


def mikrotik_routeros(html: str | None = None) -> list[VendorItem]:
    """Версии RouterOS с датами релиза.

    Ищем пары «версия — дата» в тексте страницы, не завязываясь на классы:
    вёрстку вендор меняет чаще, чем формат версии.
    """
    html = _text(MIKROTIK_CHANGELOGS) if html is None else html
    flat = _clean(html)

    seen: set[str] = set()
    out: list[VendorItem] = []
    # 7.23.5 ... 2026-09-04  (между ними может быть слово-метка ветки)
    for ver, branch, date in re.findall(
        r"\b(\d+\.\d+(?:\.\d+)?)\b[^0-9]{0,40}?"
        r"(long-term|stable|testing|development)?[^0-9]{0,20}?"
        r"(\d{4}-\d{2}-\d{2})",
        flat,
        flags=re.I,
    ):
        if ver in seen:
            continue
        seen.add(ver)
        label = f" ({branch.lower()})" if branch else ""
        out.append(VendorItem(
            vendor="MikroTik",
            kind="fw",
            title=f"RouterOS {ver}{label}",
            url=MIKROTIK_CHANGELOGS,
            date=date,
            body="Ветка обновлена. Changelog смотреть на странице загрузок.",
        ))
    return out


MONTHS = {m: i for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july",
     "august", "september", "october", "november", "december"], 1)}


def ubiquiti_blog(html: str | None = None) -> list[VendorItem]:
    """Посты blog.ui.com: заголовок, ссылка, дата."""
    html = _text(UI_BLOG) if html is None else html

    out: list[VendorItem] = []
    seen: set[str] = set()
    # <a href="/article/...">Заголовок</a> ... September 3, 2026
    for href, chunk in re.findall(
        r'<a[^>]+href="((?:https://blog\.ui\.com)?/article/[^"]+)"[^>]*>(.{0,600}?)</a>',
        html, flags=re.S | re.I,
    ):
        url = href if href.startswith("http") else "https://blog.ui.com" + href
        if url in seen:
            continue
        title = _clean(chunk)
        if not title:
            continue
        seen.add(url)

        date = None
        m = re.search(r"([A-Z][a-z]+)\s+(\d{1,2}),\s+(\d{4})", chunk)
        if m and m.group(1).lower() in MONTHS:
            date = f"{m.group(3)}-{MONTHS[m.group(1).lower()]:02d}-{int(m.group(2)):02d}"

        kind = "fw" if re.search(r"\b(\d+\.\d+|release|update)\b", title, re.I) else "new"
        out.append(VendorItem(vendor="Ubiquiti", kind=kind, title=title,
                              url=url, date=date))
    return out


SOURCES = {
    "mikrotik": mikrotik_routeros,
    "ubiquiti": ubiquiti_blog,
}
