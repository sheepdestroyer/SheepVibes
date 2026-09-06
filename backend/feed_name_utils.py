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
    brand_from_domain = KNOWN_DOMAIN_BRANDS.get(domain) if domain else None

    if not raw_title or not isinstance(raw_title, str):
        cleaned_title = ""
    else:
        cleaned_title = html.unescape(raw_title.strip())
    # Normalize excessive internal whitespace
    cleaned_title = re.sub(r"\s+", " ", cleaned_title).strip()

    if not cleaned_title or bool(_GENERIC_BRIDGE_TITLE_PATTERN.match(cleaned_title)):
        if brand_from_domain:
            return brand_from_domain
        if domain:
            return _format_domain_as_name(domain)
        return ""

    # Check if cleaned_title starts with a domain name
    domain_match = _DOMAIN_IN_TITLE_PATTERN.match(cleaned_title)
    if domain_match:
        extracted_domain = domain_match.group(1).lower()
        if extracted_domain in KNOWN_DOMAIN_BRANDS:
            return KNOWN_DOMAIN_BRANDS[extracted_domain]

    # Strip common boilerplate prefixes (e.g., "Latest from Tom's Hardware" -> "Tom's Hardware")
    cleaned_title = _BOILERPLATE_PREFIX_PATTERN.sub("", cleaned_title).strip()

    # Strip common boilerplate suffixes (e.g., "Ars Technica - All content" -> "Ars Technica")
    cleaned_title = _BOILERPLATE_SUFFIX_PATTERN.sub("", cleaned_title).strip()

    # If title starts with or equals domain brand (e.g. "Le Monde.fr" -> "Le Monde")
    if brand_from_domain:
        # If title is equal to brand with a TLD suffix like ".fr", ".com"
        clean_no_tld = re.sub(
            r"\.(?:fr|com|org|net|co\.uk|io|de|eu)$",
            "",
            cleaned_title,
            flags=re.IGNORECASE,
        ).strip()
        if clean_no_tld.lower() == brand_from_domain.lower():
            return brand_from_domain

        # If title starts with brand name + delimiter/TLD
        brand_lower = brand_from_domain.lower()
        if (
            clean_no_tld.lower().startswith(brand_lower)
            and len(clean_no_tld) <= len(brand_lower) + 4
        ):
            return brand_from_domain

        # If the title is a pure tagline or marketing slogan that does not contain the brand name
        brand_no_spaces = brand_lower.replace(" ", "")
        title_no_spaces = cleaned_title.lower().replace(" ", "")
        if brand_no_spaces not in title_no_spaces:
            # Check if title looks like a generic tagline (e.g., long keyword list)
            if len(cleaned_title) >= 30 and (
                "," in cleaned_title or bool(_GENERIC_TAGLINE_PATTERN.search(cleaned_title))
            ):
                return brand_from_domain

    # If title still has delimiters like " - ", " | ", " — ", " – ", check if one side is the brand
    for sep in (" – ", " — ", " - ", " | ", " :: ", " » ", " • "):
        if sep not in cleaned_title:
            continue
        parts = [p.strip() for p in cleaned_title.split(sep) if p.strip()]
        if len(parts) < 2:
            continue
        # Check if right part matches known brand or domain
        # e.g., "Artificial intelligence – MIT Technology Review"
        if brand_from_domain and parts[-1].lower() == brand_from_domain.lower():
            return brand_from_domain
        # If left part matches known brand (e.g. "Ars Technica - Articles")
        if brand_from_domain and parts[0].lower() == brand_from_domain.lower():
            return brand_from_domain
        # If left part is a clean short name, strip trailing TLDs if present
        left_part = re.sub(
            r"\.(?:fr|com|org|net|co\.uk|io|de|eu)$",
            "",
            parts[0],
            flags=re.IGNORECASE,
        ).strip()
        if brand_from_domain and left_part.lower() == brand_from_domain.lower():
            return brand_from_domain
        if len(parts[0]) <= 30 and not _BOILERPLATE_SUFFIX_PATTERN.search(parts[0]):
            if parts[0].lower() in (
                "changelog",
                "releases",
                "release",
                "updates",
                "blog",
                "news",
                "articles",
                "documentation",
                "docs",
            ):
                if brand_from_domain:
                    return brand_from_domain
                return parts[-1]
            return parts[0]

    # Strip domain suffix like ".com", ".fr" if it was "DistroWatch.com" or "Le Monde.fr"
    cleaned_no_tld = re.sub(
        r"\.(?:fr|com|org|net|co\.uk|io|de|eu)$",
        "",
        cleaned_title,
        flags=re.IGNORECASE,
    ).strip()
    if brand_from_domain and cleaned_no_tld.lower() == brand_from_domain.lower():
        return brand_from_domain
    if cleaned_title.lower().endswith(".com") and len(cleaned_title) > 4:
        name_without_tld = cleaned_title[:-4]
        if name_without_tld.lower() in ("distrowatch", "slashdot", "phoronix"):
            return name_without_tld.capitalize()

    # Strip any dangling delimiters at ends
    cleaned_title = cleaned_title.strip(" -|:—–»•~").strip()

    return cleaned_title if cleaned_title else (
        brand_from_domain or _format_domain_as_name(domain or "") or ""
    )
