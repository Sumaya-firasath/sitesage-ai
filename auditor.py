"""auditor.py - safely fetches a web page and runs the SEO checks.

Nothing in here is invented: every result comes from the HTML that was
actually downloaded from the URL you entered.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urldefrag, urljoin, urlparse

import pandas as pd
import requests
from bs4 import BeautifulSoup

USER_AGENT = "SiteSageBot/1.0 (educational SEO audit tool)"
TIMEOUT = (5, 10)            # (connect seconds, read seconds)
MAX_BYTES = 2_000_000        # never download more than ~2 MB
MAX_REDIRECTS = 5
ALLOWED_PORTS = {None, 80, 443}


class AuditError(Exception):
    """Raised with a friendly message when an audit cannot be completed."""


# ----------------------------------------------------------------------------
# 1. Safe fetching
# ----------------------------------------------------------------------------
def normalize_url(raw: str) -> str:
    """Validate the URL text and add https:// if the scheme is missing."""
    raw = (raw or "").strip()
    if not raw:
        raise AuditError("Please enter a website URL.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        port = parsed.port
    except ValueError:
        raise AuditError("That URL is not valid. Example: https://example.com")
    if parsed.scheme not in ("http", "https"):
        raise AuditError("Only http:// and https:// URLs are allowed.")
    if not parsed.hostname:
        raise AuditError("That URL has no website name in it.")
    if parsed.username or parsed.password:
        raise AuditError("URLs containing a username or password are not allowed.")
    if port not in ALLOWED_PORTS:
        raise AuditError("Only the standard web ports (80 and 443) are allowed.")
    return raw


def assert_public_host(hostname: str) -> None:
    """Block hosts that resolve to private/internal/reserved IP addresses."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise AuditError(f"Could not find '{hostname}'. Check the spelling of the address.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            raise AuditError(
                "That address points to a private or internal network, "
                "so it was blocked for safety."
            )


@dataclass
class FetchResult:
    final_url: str
    status_code: int
    seconds: float
    content: bytes
    redirects: list = field(default_factory=list)
    truncated: bool = False


def fetch_page(url: str) -> FetchResult:
    """Download the page. Redirects are followed manually so that EVERY hop is re-checked."""
    current = normalize_url(url)
    redirects: list[str] = []
    started = time.perf_counter()

    for _ in range(MAX_REDIRECTS + 1):
        assert_public_host(urlparse(current).hostname)
        try:
            resp = requests.get(
                current,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
        except requests.exceptions.Timeout:
            raise AuditError("The website took too long to respond (timeout).")
        except requests.exceptions.SSLError:
            raise AuditError("The website has an invalid or untrusted HTTPS certificate.")
        except requests.exceptions.ConnectionError:
            raise AuditError("Could not connect to the website. It may be down or blocking requests.")
        except requests.exceptions.RequestException as exc:
            raise AuditError(f"The request failed ({exc.__class__.__name__}).")

        if resp.is_redirect:
            nxt = normalize_url(urljoin(current, resp.headers["Location"]))
            resp.close()
            redirects.append(nxt)
            current = nxt
            continue
        break
    else:
        raise AuditError("The website redirected too many times.")

    try:
        if resp.status_code >= 400:
            raise AuditError(f"The website returned HTTP error {resp.status_code}.")
        ctype = resp.headers.get("Content-Type", "").lower()
        if ctype and "html" not in ctype:
            raise AuditError("That URL is not a web page (it did not return HTML).")
        chunks, size, truncated = [], 0, False
        for chunk in resp.iter_content(65536):
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BYTES:
                truncated = True
                break
        content = b"".join(chunks)[:MAX_BYTES]
        status = resp.status_code
    except requests.exceptions.RequestException:
        raise AuditError("The connection dropped while downloading the page.")
    finally:
        resp.close()

    return FetchResult(current, status, time.perf_counter() - started, content, redirects, truncated)


# ----------------------------------------------------------------------------
# 2. Data structures
# ----------------------------------------------------------------------------
@dataclass
class Check:
    category: str
    name: str
    status: str            # "pass" | "warning" | "fail" | "info"
    finding: str
    recommendation: str
    weight: int            # points available; info checks are not scored

    @property
    def earned(self) -> float:
        return {"pass": 1.0, "warning": 0.5}.get(self.status, 0.0) * self.weight


@dataclass
class AuditResult:
    requested_url: str
    final_url: str
    status_code: int
    seconds: float
    size_kb: float
    truncated: bool
    audited_at: datetime
    checks: list
    title: str
    meta_description: str
    headings: list          # [(level, text), ...]
    images: list            # [{"src":..., "alt_status":..., "alt":...}]
    internal_links: list    # [{"url":..., "text":...}]
    external_links: list
    score: int
    grade: str

    def count(self, status: str) -> int:
        return sum(1 for c in self.checks if c.status == status)


def grade_for(score: int) -> str:
    if score >= 85:
        return "Excellent"
    if score >= 70:
        return "Good"
    if score >= 50:
        return "Needs work"
    return "Poor"


def score_color(score: int) -> str:
    return "#16A34A" if score >= 80 else "#D97706" if score >= 50 else "#DC2626"


# ----------------------------------------------------------------------------
# 3. The analysis itself
# ----------------------------------------------------------------------------
def _host(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def analyze(fetch: FetchResult, requested_url: str = "") -> AuditResult:
    soup = BeautifulSoup(fetch.content, "html.parser")
    checks: list[Check] = []
    final_url = fetch.final_url

    # --- HTTPS (15 pts) ---
    if urlparse(final_url).scheme == "https":
        checks.append(Check("Security", "HTTPS", "pass",
                            "The page is served over HTTPS (certificate accepted).", "", 15))
    else:
        checks.append(Check("Security", "HTTPS", "fail",
                            "The page is served over plain HTTP.",
                            "Install an SSL certificate and redirect all HTTP traffic to HTTPS.", 15))

    # --- Title (20 pts) ---
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    n = len(title)
    if n == 0:
        checks.append(Check("On-page", "Page title", "fail", "No <title> tag found (or it is empty).",
                            "Add a unique, descriptive title of about 30-60 characters containing your main topic.", 20))
    elif 30 <= n <= 60:
        checks.append(Check("On-page", "Page title", "pass",
                            f"Title found ({n} characters), within the commonly recommended 30-60 range.", "", 20))
    else:
        issue = "short and may under-describe the page" if n < 30 else "long and may be truncated in search results"
        checks.append(Check("On-page", "Page title", "warning", f"Title is {n} characters: it is {issue}.",
                            "Rewrite the title to roughly 30-60 characters, keeping the main keyword near the start.", 20))

    # --- Meta description (10 pts) ---
    tag = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    meta = (tag.get("content") or "").strip() if tag else ""
    n = len(meta)
    if n == 0:
        checks.append(Check("On-page", "Meta description", "fail", "No meta description found (or it is empty).",
                            "Add a meta description of about 70-160 characters that summarises the page and encourages clicks.", 10))
    elif 70 <= n <= 160:
        checks.append(Check("On-page", "Meta description", "pass",
                            f"Meta description found ({n} characters), within the commonly recommended 70-160 range.", "", 10))
    else:
        issue = "short" if n < 70 else "long and may be truncated"
        checks.append(Check("On-page", "Meta description", "warning", f"Meta description is {n} characters: it is {issue}.",
                            "Aim for roughly 70-160 characters.", 10))

    # --- Headings ---
    headings = [(int(t.name[1]), t.get_text(" ", strip=True)) for t in soup.find_all(re.compile(r"^h[1-6]$"))]
    h1s = [text for level, text in headings if level == 1]

    # H1 (15 pts)
    if len(h1s) == 0:
        checks.append(Check("On-page", "H1 heading", "fail", "No H1 heading found.",
                            "Add exactly one H1 that clearly describes the page topic.", 15))
    elif len(h1s) == 1 and h1s[0]:
        checks.append(Check("On-page", "H1 heading", "pass", f"Exactly one H1 found: \"{h1s[0][:80]}\".", "", 15))
    elif len(h1s) == 1:
        checks.append(Check("On-page", "H1 heading", "warning", "The only H1 is empty.",
                            "Put descriptive text inside your H1.", 15))
    else:
        checks.append(Check("On-page", "H1 heading", "warning", f"{len(h1s)} H1 headings found.",
                            "Use a single H1 per page and demote the others to H2/H3.", 15))

    # Heading structure (10 pts)
    skips, prev = [], 0
    for level, _ in headings:
        if prev and level > prev + 1:
            skips.append(f"H{prev} to H{level}")
        prev = level
    empty = sum(1 for _, text in headings if not text)
    has_h2 = any(level == 2 for level, _ in headings)
    if not headings:
        checks.append(Check("On-page", "Heading structure", "fail", "The page has no headings at all.",
                            "Organise content with one H1 followed by H2 sections (and H3 sub-sections).", 10))
    elif skips or empty or not has_h2:
        problems = []
        if skips:
            problems.append("skipped levels (" + ", ".join(skips[:3]) + ")")
        if empty:
            problems.append(f"{empty} empty heading(s)")
        if not has_h2:
            problems.append("no H2 sub-headings")
        checks.append(Check("On-page", "Heading structure", "warning",
                            f"{len(headings)} headings found, but: " + "; ".join(problems) + ".",
                            "Use headings in order (H1, then H2, then H3), never skip levels, and avoid empty headings.", 10))
    else:
        checks.append(Check("On-page", "Heading structure", "pass",
                            f"{len(headings)} headings found in a logical order.", "", 10))

    # --- Images / alt text (15 pts) ---
    images = []
    for img in soup.find_all("img"):
        alt = img.get("alt")
        status = "Missing" if alt is None else ("Empty (decorative?)" if not alt.strip() else "Present")
        images.append({"src": img.get("src") or img.get("data-src") or "(no src)",
                       "alt_status": status, "alt": (alt or "").strip()})
    missing = sum(1 for i in images if i["alt_status"] == "Missing")
    if not images:
        checks.append(Check("Content", "Image alt text", "info", "No <img> tags found, so this check was not scored.", "", 15))
    elif missing == 0:
        checks.append(Check("Content", "Image alt text", "pass",
                            f"All {len(images)} images have an alt attribute.", "", 15))
    else:
        pct = missing / len(images)
        checks.append(Check("Content", "Image alt text", "warning" if pct <= 0.2 else "fail",
                            f"{missing} of {len(images)} images have no alt attribute ({pct:.0%}).",
                            "Add short, descriptive alt text to meaningful images (use alt=\"\" only for purely decorative ones).", 15))

    # --- Links (internal 15 pts, external informational) ---
    internal, external = {}, {}
    page_host = _host(final_url)
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.lower().startswith(("#", "mailto:", "tel:", "javascript:", "sms:")):
            continue
        absolute = urldefrag(urljoin(final_url, href))[0]
        if urlparse(absolute).scheme not in ("http", "https"):
            continue
        text = a.get_text(" ", strip=True)
        if not text:
            img = a.find("img")
            text = (img.get("alt") or "").strip() if img else ""
        entry = {"url": absolute, "text": text or "(no anchor text)"}
        (internal if _host(absolute) == page_host else external).setdefault(absolute, entry)
    internal_links, external_links = list(internal.values()), list(external.values())

    ni = len(internal_links)
    if ni >= 3:
        checks.append(Check("Links", "Internal links", "pass", f"{ni} unique internal links found.", "", 15))
    elif ni > 0:
        checks.append(Check("Links", "Internal links", "warning", f"Only {ni} unique internal link(s) found.",
                            "Link to more of your related pages to help visitors and crawlers discover content.", 15))
    else:
        checks.append(Check("Links", "Internal links", "fail", "No internal links found on this page.",
                            "Add links to other relevant pages on your site using descriptive anchor text.", 15))
    checks.append(Check("Links", "External links", "info",
                        f"{len(external_links)} unique external link(s) found. Informational only (not scored).", "", 0))

    # --- Score: earned points / available points of the checks that were scored ---
    scored = [c for c in checks if c.weight > 0 and c.status != "info"]
    total = sum(c.weight for c in scored)
    score = round(sum(c.earned for c in scored) / total * 100) if total else 0

    return AuditResult(
        requested_url=requested_url or final_url, final_url=final_url, status_code=fetch.status_code,
        seconds=fetch.seconds, size_kb=len(fetch.content) / 1024, truncated=fetch.truncated,
        audited_at=datetime.now(), checks=checks, title=title, meta_description=meta, headings=headings,
        images=images, internal_links=internal_links, external_links=external_links,
        score=score, grade=grade_for(score),
    )


# ----------------------------------------------------------------------------
# 4. Pandas tables (used by the dashboard and the CSV export)
# ----------------------------------------------------------------------------
def checks_df(result: AuditResult) -> pd.DataFrame:
    rows = []
    for c in result.checks:
        rows.append({
            "Category": c.category, "Check": c.name, "Status": c.status.upper(),
            "Points earned": "" if c.status == "info" else c.earned,
            "Points available": "" if c.status == "info" else c.weight,
            "Finding": c.finding, "Recommendation": c.recommendation,
        })
    return pd.DataFrame(rows)


def export_df(result: AuditResult) -> pd.DataFrame:
    df = checks_df(result)
    df.insert(0, "Audited at", result.audited_at.strftime("%Y-%m-%d %H:%M"))
    df.insert(0, "URL", result.final_url)
    df["Overall score"] = result.score
    return df


def headings_df(result: AuditResult) -> pd.DataFrame:
    return pd.DataFrame([{"Order": i + 1, "Level": f"H{lv}", "Text": tx or "(empty)"}
                         for i, (lv, tx) in enumerate(result.headings)],
                        columns=["Order", "Level", "Text"])


def images_df(result: AuditResult) -> pd.DataFrame:
    return pd.DataFrame([{"Image source": i["src"][:120], "Alt status": i["alt_status"], "Alt text": i["alt"]}
                         for i in result.images], columns=["Image source", "Alt status", "Alt text"])


def links_df(links: list) -> pd.DataFrame:
    return pd.DataFrame([{"URL": l["url"], "Anchor text": l["text"]} for l in links],
                        columns=["URL", "Anchor text"])
