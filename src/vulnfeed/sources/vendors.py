"""Автоматические вендорские источники.

Первая версия разбирала HTML страниц регулярками и провалилась предсказуемо:
MikroTik отдал одну случайную пару «версия-дата» из 2015 года, Ubiquiti —
ноль. Теперь оба источника взяты там, где у вендора есть машиночитаемый вход:

  MikroTik  — download.mikrotik.com/routeros/latest-stable-and-long-term.rss,
              честный RSS 2.0 с заголовком вида «RouterOS 7.23.5 [long-term]»
              и pubDate;
  Ubiquiti  — blog.ui.com/sitemap.xml даёт список статей, но lastmod у всех
              одинаковый и бесполезен, поэтому дата берётся со страницы самой
              статьи (текстом, вида «April 29, 2026»; метатегов там нет).
              Уже известные URL повторно не запрашиваются.

Не берутся и подключены быть не могут: форум MikroTik (robots.txt),
omadanetworks.com/press (403), RUCKUS (за логином), Dahua (403 + robots).
Для них есть vendor_feed.toml.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from xml.etree import ElementTree as ET

import httpx

from ..models import VendorItem

MIKROTIK_RSS = "https://download.mikrotik.com/routeros/latest-stable-and-long-term.rss"
UI_SITEMAP = "https://blog.ui.com/sitemap.xml"

UA = {"User-Agent": "vulnfeed/0.1 (personal vendor tracker)"}

# Автопарсер не должен затаскивать древность: если источник вдруг отдаст
# архив, лента забьётся мусором, как это уже случилось с RouterOS 6.30.1.
MAX_AGE_DAYS = 900

MONTHS = {m: i for i, m in enumerate(
    ["january", "february", "march", "april", "may", "june", "july",
     "august", "september", "october", "november", "december"], 1)}


def _get(url: str, timeout: float = 45.0) -> str:
    resp = httpx.get(url, timeout=timeout, headers=UA, follow_redirects=True)
    resp.raise_for_status()
    return resp.text


def _too_old(date: str | None) -> bool:
    if not date:
        return False
    cutoff = (datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)).strftime("%Y-%m-%d")
    return date < cutoff


def _text_date(chunk: str) -> str | None:
    """«April 29, 2026» → «2026-04-29»."""
    m = re.search(r"\b([A-Z][a-z]+)\s+(\d{1,2}),\s+(\d{4})\b", chunk)
    if not m or m.group(1).lower() not in MONTHS:
        return None
    return f"{m.group(3)}-{MONTHS[m.group(1).lower()]:02d}-{int(m.group(2)):02d}"


# ------------------------------------------------------------------ MikroTik

def mikrotik_routeros(xml: str | None = None) -> list[VendorItem]:
    xml = _get(MIKROTIK_RSS) if xml is None else xml
    root = ET.fromstring(xml)

    out: list[VendorItem] = []
    for item in root.iterfind(".//item"):
        title = (item.findtext("title") or "").strip()
        if not title:
            continue
        link = (item.findtext("link") or MIKROTIK_RSS).strip()

        date = None
        pub = item.findtext("pubDate")
        if pub:
            try:
                date = parsedate_to_datetime(pub).strftime("%Y-%m-%d")
            except (TypeError, ValueError):
                date = None
        if _too_old(date):
            continue

        body = None
        raw = item.findtext("{http://purl.org/rss/1.0/modules/content/}encoded") or \
            item.findtext("description")
        if raw:
            body = re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", raw))).strip()
            if len(body) > 400:
                body = body[:397] + "…"

        out.append(VendorItem(vendor="MikroTik", kind="fw", title=title,
                              url=link, date=date, body=body))
    return out


# ------------------------------------------------------------------ Ubiquiti

def _ui_article_urls(sitemap_xml: str) -> list[str]:
    root = ET.fromstring(sitemap_xml)
    urls = []
    for loc in root.iterfind(".//{*}url/{*}loc"):
        u = (loc.text or "").strip()
        if "/article/" in u:
            urls.append(u)
    return urls


def _ui_parse_article(url: str, html: str) -> VendorItem:
    title = None
    m = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S | re.I) or \
        re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    if m:
        title = re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", m.group(1)))).strip()
        title = re.sub(r"\s*[|–—-]\s*(Ubiquiti|UI\.com|Blog).*$", "", title).strip()
    if not title:
        # запасной вариант: собрать из слага, чтобы запись не осталась безымянной
        title = url.rstrip("/").rsplit("/", 1)[-1].replace("-", " ").capitalize()

    date = _text_date(html[:20000])
    kind = "fw" if re.search(r"\b\d+\.\d+\b|release|update", title, re.I) else "new"
    return VendorItem(vendor="Ubiquiti", kind=kind, title=title, url=url, date=date)


def ubiquiti_blog(known_urls: set[str] | None = None, limit: int = 15,
                  sitemap_xml: str | None = None,
                  fetch=None) -> list[VendorItem]:
    """Новые статьи блога. Уже известные URL повторно не запрашиваются."""
    known = known_urls or set()
    fetch = fetch or _get
    sitemap_xml = _get(UI_SITEMAP) if sitemap_xml is None else sitemap_xml

    out: list[VendorItem] = []
    for url in _ui_article_urls(sitemap_xml):
        if url in known:
            continue
        if len(out) >= limit:
            break
        try:
            item = _ui_parse_article(url, fetch(url))
        except Exception:
            continue  # одна недоступная статья не должна ронять источник
        if _too_old(item.date):
            continue
        out.append(item)
    return out


SOURCES = {
    "mikrotik": lambda known=None: mikrotik_routeros(),
    "ubiquiti": lambda known=None: ubiquiti_blog(known),
}
