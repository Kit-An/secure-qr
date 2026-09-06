import hashlib
import posixpath
import re
import urllib.parse


def clean_and_unescape(url: str) -> str:
    """Strips tabs/CR/LF, drops fragments, and unescapes recursively."""
    url = re.sub(r"[\t\r\n]", "", url.strip())
    if "#" in url:
        url = url.split("#", 1)[0]
    while True:
        unescaped = urllib.parse.unquote(url)
        if unescaped == url:
            break
        url = unescaped
    return url


def escape_char(char: str) -> str:
    """Escape characters unsafe in the canonical URL representation."""
    codepoint = ord(char)
    if codepoint <= 32 or char in ("#", "%"):
        return f"%{codepoint:02X}"
    if codepoint >= 127:
        return "".join(f"%{byte:02X}" for byte in char.encode("utf-8"))
    return char


def reescape_string(s: str) -> str:
    return "".join(escape_char(c) for c in s)


def parse_ip_component(part: str) -> int | None:
    part = part.strip()
    try:
        if part.lower().startswith("0x"):
            return int(part, 16)
        if (
            part.startswith("0")
            and len(part) > 1
            and not part.startswith("0.")
        ):
            return int(part, 8)
        return int(part, 10)
    except ValueError:
        return None


def canonicalize_ipv4(host: str) -> str:
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        return host

    parsed: list[int] = []
    for part in parts:
        value = parse_ip_component(part)
        if value is None or value < 0:
            return host
        parsed.append(value)

    if len(parsed) == 1:
        val = parsed[0]
        if val > 0xFFFFFFFF:
            return host
        b = [
            (val >> 24) & 0xFF,
            (val >> 16) & 0xFF,
            (val >> 8) & 0xFF,
            val & 0xFF,
        ]
    elif len(parsed) == 2:
        if parsed[0] > 0xFF or parsed[1] > 0xFFFFFF:
            return host
        b = [
            parsed[0],
            (parsed[1] >> 16) & 0xFF,
            (parsed[1] >> 8) & 0xFF,
            parsed[1] & 0xFF,
        ]
    elif len(parsed) == 3:
        if parsed[0] > 0xFF or parsed[1] > 0xFF or parsed[2] > 0xFFFF:
            return host
        b = [
            parsed[0],
            parsed[1],
            (parsed[2] >> 8) & 0xFF,
            parsed[2] & 0xFF,
        ]
    else:
        if any(p > 0xFF for p in parsed):
            return host
        b = parsed

    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def canonicalize_url(raw_url: str) -> tuple[str, str, str]:
    """Returns normalized (host, path, query)."""
    url = clean_and_unescape(raw_url)
    if "://" in url:
        _, rest = url.split("://", 1)
    else:
        rest = url

    if "/" in rest:
        host, path_query = rest.split("/", 1)
        path_query = "/" + path_query
    elif "?" in rest:
        host, path_query = rest.split("?", 1)
        path_query = "/?" + path_query
    else:
        host = rest
        path_query = "/"

    if "?" in path_query:
        path, query = path_query.split("?", 1)
        query = "?" + query
    else:
        path = path_query
        query = ""

    host = host.lower()
    host = re.sub(r"^\.+|\.+$", "", host)
    host = re.sub(r"\.+", ".", host)
    host = canonicalize_ipv4(host)
    host = reescape_string(host)

    path = re.sub(r"/+", "/", path)
    has_trailing_slash = path.endswith("/")
    path = posixpath.normpath(path)
    if has_trailing_slash and not path.endswith("/"):
        path += "/"
    if not path.startswith("/"):
        path = "/" + path

    path = reescape_string(path)
    query = reescape_string(query)
    return host, path, query


def get_lookup_expressions(raw_url: str) -> list[str]:
    """Generate host/path combinations for database and prefix checks."""
    host, path, query = canonicalize_url(raw_url)

    # Host expressions (max 5)
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
        hosts = [host]
    else:
        parts = host.split(".")
        hosts = [host]
        start_index = max(1, len(parts) - 5)
        for i in range(start_index, len(parts) - 1):
            suffix = ".".join(parts[i:])
            if suffix not in hosts:
                hosts.append(suffix)

    # Path expressions (max 6)
    paths = []
    if query:
        paths.append(path + query)
    if path not in paths:
        paths.append(path)
    segments = [s for s in path.split("/") if s]
    cur = "/"
    for i in range(min(4, len(segments))):
        cur += segments[i] + "/"
        if cur not in paths:
            paths.append(cur)
    if "/" not in paths:
        paths.append("/")

    expressions = []
    for h in hosts:
        for p in paths:
            expressions.append(f"{h}{p}")
    return expressions


def get_canonical_cache_key(raw_url: str) -> str:
    """Generates a consistent SHA-256 hash string from the canonical URL."""
    host, path, query = canonicalize_url(raw_url)
    full_canonical = f"https://{host}{path}{query}"
    return hashlib.sha256(full_canonical.encode("utf-8")).hexdigest()
