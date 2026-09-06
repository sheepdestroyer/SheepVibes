"""Utilities for cleaning and deriving canonical short website/feed names."""
# pylint: disable=too-many-locals,too-many-return-statements,too-many-branches,broad-exception-caught

from __future__ import annotations

import html
import re
from urllib.parse import urlparse

# Known domain-to-brand mapping for common feeds/aggregators
KNOWN_DOMAIN_BRANDS: dict[str, str] = {
    "wccftech.com": "Wccftech",
    "theregister.com": "The Register",
    "theregister.co.uk": "The Register",
    "tomshardware.com": "Tom's Hardware",
    "arstechnica.com": "Ars Technica",
    "anandtech.com": "AnandTech",
    "theverge.com": "The Verge",
    "lemonde.fr": "Le Monde",
    "liberation.fr": "Libération",
    "slashdot.org": "Slashdot",
    "phoronix.com": "Phoronix",
    "gamersnexus.net": "GamersNexus",
    "distrowatch.com": "DistroWatch",
    "kernel.org": "Kernel.org",
    "kernelplanet.org": "Kernel Planet",
    "lwn.net": "LWN.net",
    "technologyreview.com": "MIT Technology Review",
    "semiaccurate.com": "Semiaccurate",
    "realworldtech.com": "Real World Tech",
    "krebsonsecurity.com": "Krebs on Security",
    "korben.info": "Korben",
    "nytimes.com": "The New York Times",
    "news.ycombinator.com": "Hacker News",
    "lobste.rs": "Lobsters",
    "steampowered.com": "Steam",
    "steamcommunity.com": "Steam Community",
    "steamdb.info": "SteamDB",
    "roadtovr.com": "Road to VR",
    "uploadvr.com": "UploadVR",
    "nofrag.com": "NoFrag",
    "kguttag.com": "KGOnTech",
    "stallman.org": "Richard Stallman",
    "slate.fr": "Slate.fr",
    "antigravity.google": "Google Antigravity",
    "jules.google": "Jules",
    "lucebox.com": "Lucebox",
}

# Regex to detect generic RSS-Bridge and GenericChangelog bridge artifact titles
_GENERIC_BRIDGE_TITLE_PATTERN = re.compile(
    r"^(?:generic\s+changelog.*|rss-bridge|bridge)\s*$",
    re.IGNORECASE,
)

# Regex to strip common boilerplate suffixes from feed titles
_BOILERPLATE_SUFFIX_PATTERN = re.compile(
    r"\s*(?:[-|:—–»•~]\s*|\s+-\s+)(?:"
    r"articles|"
    r"news|"
    r"all content|"
    r"all posts|"
    r"latest stories|"
    r"latest news|"
    r"latest posts|"
    r"rss feed|"
    r"rss 2\.0|"
    r"rss|"
    r"atom feed|"
    r"atom|"
    r"front page|"
    r"homepage|"
    r"home|"
    r"feed|"
    r"headlines|"
    r"daily|"
    r"posts|"
    r"une|"
    r"actualit[ée]s.*|"
    r"graphics card & processor news|"
    r"changelog|"
    r"releases?|"
    r"updates?"
    r")\s*$",
    re.IGNORECASE,
)

# Regex to strip common boilerplate prefixes from feed titles
_BOILERPLATE_PREFIX_PATTERN = re.compile(
    r"^(?:latest from|rss feed for|news from|rss:\s*|feed:\s*|"
    r"(?:changelog|releases?|updates?|blog)\s*[-|:—–»•~]\s*)\s*",
    re.IGNORECASE,
)

# Regex to detect domain names in title strings (e.g., "www.theregister.com - Articles")
_DOMAIN_IN_TITLE_PATTERN = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)",
    re.IGNORECASE,
)

# Regex for generic tagline patterns that lack a distinct brand name
_GENERIC_TAGLINE_PATTERN = re.compile(
    r"(?:news|reviews|guides|pc hardware|hardware news|graphics card|processor|articles|updates)",
    re.IGNORECASE,
)


def _extract_domain(url: str | None) -> str | None:
    """Extracts a normalized hostname/domain from a URL."""
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url.strip())
        host = parsed.hostname or parsed.netloc
        if not host:
            return None
        host = host.lower()
        if host.startswith("www."):
            host = host[4:]
        # Remove port if present
        if ":" in host:
            host = host.split(":")[0]
        return host if host else None
    except Exception:
        return None


def _format_domain_as_name(domain: str) -> str:
    """Formats a domain string into a human-readable title fallback."""
    if not domain:
        return ""
    parts = domain.split(".")
    if len(parts) >= 2:
        main_name = parts[0]
        return main_name.capitalize()
    return domain.capitalize()


def _clean_raw_title(raw_title: str | None) -> str:
    """Unescapes and normalizes whitespace in raw title string."""
    if not raw_title or not isinstance(raw_title, str):
        return ""
    cleaned = html.unescape(raw_title.strip())
    return re.sub(r"\s+", " ", cleaned).strip()


def _is_generic_bridge_title(title: str) -> bool:
    """Checks if a title matches generic RSS-Bridge or bridge fallback names."""
    return bool(_GENERIC_BRIDGE_TITLE_PATTERN.match(title))


def _strip_title_boilerplate(title: str) -> str:
    """Strips leading and trailing boilerplate prefixes/suffixes from title."""
    title = _BOILERPLATE_PREFIX_PATTERN.sub("", title).strip()
    return _BOILERPLATE_SUFFIX_PATTERN.sub("", title).strip()


def _match_domain_in_title(title: str) -> str | None:
    """Checks if title begins with a recognized domain name."""
    domain_match = _DOMAIN_IN_TITLE_PATTERN.match(title)
    if domain_match:
        extracted = domain_match.group(1).lower()
        return KNOWN_DOMAIN_BRANDS.get(extracted)
    return None


def _match_brand_heuristics(title: str, brand: str) -> bool:
    """Checks whether title matches known brand heuristics (TLDs or taglines)."""
    clean_no_tld = re.sub(
        r"\.(?:fr|com|org|net|co\.uk|io|de|eu)$",
        "",
        title,
        flags=re.IGNORECASE,
    ).strip()
    brand_lower = brand.lower()

    if clean_no_tld.lower() == brand_lower:
        return True
    if clean_no_tld.lower().startswith(brand_lower) and len(clean_no_tld) <= len(brand_lower) + 4:
        return True

    brand_no_spaces = brand_lower.replace(" ", "")
    title_no_spaces = title.lower().replace(" ", "")
    if brand_no_spaces not in title_no_spaces:
        if len(title) >= 30 and ("," in title or bool(_GENERIC_TAGLINE_PATTERN.search(title))):
            return True
    return False


_DELIMITERS = (" – ", " — ", " - ", " | ", " :: ", " » ", " • ")
_SECTION_KEYWORDS = frozenset({
    "changelog",
    "releases",
    "release",
    "updates",
    "blog",
    "news",
    "articles",
    "documentation",
    "docs",
})


def _match_parts_brand(parts: list[str], brand: str | None) -> str | None:
    """Checks if first or last delimited part matches known brand."""
    if not brand:
        return None
    brand_lower = brand.lower()
    if parts[-1].lower() == brand_lower or parts[0].lower() == brand_lower:
        return brand
    left_no_tld = re.sub(
        r"\.(?:fr|com|org|net|co\.uk|io|de|eu)$", "", parts[0], flags=re.IGNORECASE
    ).strip()
    if left_no_tld.lower() == brand_lower:
        return brand
    return None


def _extract_delimited_brand(title: str, brand: str | None) -> str | None:
    """Checks delimited parts (e.g. 'Site - Section' or 'Changelog | Brand') for brands."""
    for sep in _DELIMITERS:
        if sep not in title:
            continue
        parts = [p.strip() for p in title.split(sep) if p.strip()]
        if len(parts) < 2:
            continue

        brand_match = _match_parts_brand(parts, brand)
        if brand_match:
            return brand_match

        if len(parts[0]) <= 30 and not _BOILERPLATE_SUFFIX_PATTERN.search(parts[0]):
            if parts[0].lower() in _SECTION_KEYWORDS:
                return brand or parts[-1]
            return parts[0]
    return None


def _clean_known_tld_suffix(title: str, brand: str | None) -> str | None:
    """Strips recognized TLD suffixes if matching a known brand or tech site."""
    clean_no_tld = re.sub(
        r"\.(?:fr|com|org|net|co\.uk|io|de|eu)$", "", title, flags=re.IGNORECASE
    ).strip()
    if brand and clean_no_tld.lower() == brand.lower():
        return brand
    if title.lower().endswith(".com") and len(title) > 4:
        name = title[:-4]
        if name.lower() in ("distrowatch", "slashdot", "phoronix"):
            return name.capitalize()
    return None


def _find_title_candidate(title: str, brand: str | None) -> str | None:
    """Evaluates title against domain matching, brand heuristics, delimiters, and TLD rules."""
    domain_title = _match_domain_in_title(title)
    if domain_title:
        return domain_title
    if brand and _match_brand_heuristics(title, brand):
        return brand
    delimited = _extract_delimited_brand(title, brand)
    if delimited:
        return delimited
    return _clean_known_tld_suffix(title, brand)


def derive_canonical_feed_name(
    raw_title: str | None,
    site_url: str | None = None,
    feed_url: str | None = None,
) -> str:
    """Derives a concise, canonical website/feed name from title and URLs.

    Args:
        raw_title: The raw feed or outline title string.
        site_url: Optional website link URL.
        feed_url: Optional feed XML URL.

    Returns:
        A cleaned, canonical short feed name.
    """
    domain = _extract_domain(site_url) or _extract_domain(feed_url)
    brand = KNOWN_DOMAIN_BRANDS.get(domain) if domain else None
    fallback = brand or _format_domain_as_name(domain or "")

    title = _clean_raw_title(raw_title)
    if not title or _is_generic_bridge_title(title):
        return fallback

    title = _strip_title_boilerplate(title)
    candidate = _find_title_candidate(title, brand)
    if candidate:
        return candidate

    title = title.strip(" -|:—–»•~").strip()
    return title or fallback

