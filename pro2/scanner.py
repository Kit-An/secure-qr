"""URL safety heuristics and Google Safe Browsing integration."""

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from cache import SafeBrowsingCache
from canonicalizer import get_canonical_cache_key

SAFE_BROWSING_API_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly"
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "buzz", "gq", "cf", "ml", "tk", "ga"
}

cache = SafeBrowsingCache()


def _extract_domain_parts(url: str) -> tuple[str, str, str]:
    """Return domain parts without third-party dependencies."""
    hostname = (urllib.parse.urlparse(url).hostname or "").rstrip(".").lower()
    labels = [label for label in hostname.split(".") if label]

    if len(labels) < 2:
        return "", labels[0] if labels else "", ""

    # Handle common two-label public suffixes such as co.uk.
    two_label_suffixes = {
        "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp"
    }
    suffix_size = 2 if ".".join(labels[-2:]) in two_label_suffixes else 1
    if len(labels) <= suffix_size:
        return (
            "",
            "".join(labels[:-suffix_size]),
            ".".join(labels[-suffix_size:]),
        )

    domain_index = len(labels) - suffix_size - 1
    return (
        ".".join(labels[:domain_index]),
        labels[domain_index],
        ".".join(labels[domain_index + 1:]),
    )


def evaluate_heuristics(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    subdomain, domain, suffix = _extract_domain_parts(url)
    subdomains = subdomain.split(".") if subdomain else []

    warnings = []
    score = 0

    if parsed.scheme != "https":
        warnings.append("Connection is insecure (uses HTTP instead of HTTPS).")
        score += 1

    ip_regex = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
    if re.match(ip_regex, parsed.netloc):
        warnings.append("Direct IP address used as host.")
        score += 3

    if f"{domain}.{suffix}".lower() in SHORTENERS:
        warnings.append("URL shortener detected (hides real landing page).")
        score += 2

    if "@" in parsed.netloc:
        warnings.append(
            "Credential masking character '@' present in authority."
        )
        score += 3

    if len(subdomains) >= 3:
        warnings.append(f"High subdomain depth ({len(subdomains)} levels).")
        score += 2

    if domain.count("-") >= 2:
        warnings.append(
            "Multiple hyphens in domain label (brand spoofing risk)."
        )
        score += 1

    if suffix.lower() in SUSPICIOUS_TLDS:
        warnings.append(f"TLD .{suffix} is statistically high-risk.")
        score += 1

    if "xn--" in parsed.netloc:
        warnings.append("Punycode detected (potential homoglyph attack).")
        score += 3

    return {"score": score, "warnings": warnings}


def query_google_safe_browsing(url: str, api_key: str) -> dict:
    """Query Google Safe Browsing for threats associated with a URL."""
    cache_key = get_canonical_cache_key(url)
    cached_entry = cache.get(cache_key)
    if cached_entry:
        return cached_entry

    payload = {
        "client": {"clientId": "secureqr", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        query = urllib.parse.urlencode({"key": api_key})
        endpoint = f"{SAFE_BROWSING_API_URL}?{query}"
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))

        if "matches" in data:
            threats = list({m["threatType"] for m in data["matches"]})
            cache.set(
                cache_key, url, flagged=True, threats=threats, ttl_seconds=1800
            )
            return {
                "flagged": True,
                "threats": threats,
                "from_cache": False,
                "error": None,
            }

        cache.set(cache_key, url, flagged=False, threats=[], ttl_seconds=900)
        return {
            "flagged": False,
            "threats": [],
            "from_cache": False,
            "error": None,
        }

    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
    ) as err:
        return {
            "flagged": False,
            "threats": [],
            "from_cache": False,
            "error": str(err),
        }
