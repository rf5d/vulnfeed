from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Cve:
    cve_id: str
    vendor: str
    product: str | None = None
    title: str | None = None
    description: str | None = None
    cvss: float | None = None
    cvss_version: str | None = None
    in_kev: int = 0
    kev_date: str | None = None
    ransomware: int = 0
    published: str | None = None
    last_modified: str | None = None
    url: str | None = None

    def __post_init__(self) -> None:
        self.cve_id = self.cve_id.strip().upper()
        if self.url is None:
            self.url = f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


@dataclass
class VendorItem:
    """Запись вендорской ленты: EOL/EOS, анонс, прошивка."""

    vendor: str
    kind: str  # eol | new | fw
    title: str
    url: str
    date: str | None = None
    body: str | None = None
    hot: bool = False


@dataclass
class VendorConfig:
    name: str
    kev_match: list[str] = field(default_factory=list)
    nvd_keyword: str = ""
