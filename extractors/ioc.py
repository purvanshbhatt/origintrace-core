"""
OriginTrace — Shared IOC Patterns and String Scanning

One definition of "what counts as an indicator of compromise" for every
extractor (PE, ELF, scripts, macros). Also provides a pure-Python `strings`
replacement so binaries still yield IOCs when radare2 is not installed.
"""
import re
from typing import Iterator, List

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

# IPv4 with octet validation; rejects version-like runs such as "v1.2.3.4.5".
IPV4_RE = re.compile(rf"(?<![\w.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\w|\.\d)")
URL_RE = re.compile(r"https?://[^\s\"'`<>\\^{}|\[\]()]+", re.IGNORECASE)
# Accepts both real paths (C:\Users) and escaped source literals (C:\\Users).
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\{1,2}[^\s\"'<>|*?,;]+")
REGISTRY_RE = re.compile(r"(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\{1,2}[^\s\"',;]+")
UNIX_PATH_RE = re.compile(
    r"(?<![\w/.])(?:"
    r"/etc/(?:passwd|shadow|sudoers|crontab|ld\.so\.preload|cron\.[\w.-]+(?:/[\w.-]+)*)"
    r"|/tmp/[\w.\-/]+"
    r"|/dev/(?:tcp|udp|shm)/[\w.\-/]+"
    r"|/proc/(?:self|\d+)/[\w/]+"
    r"|/root/[\w.\-/]+"
    r"|(?:~|/home/[\w.-]+)/\.(?:ssh|aws|bash_history|bashrc|profile)[\w.\-/]*"
    r")"
)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}")

# Order matters: it is the order indicators are reported in.
IOC_PATTERNS = (URL_RE, IPV4_RE, WINDOWS_PATH_RE, REGISTRY_RE, UNIX_PATH_RE)

_TRAILING_PUNCTUATION = ".,;:!?"
_ASCII_RUN = rb"[\x20-\x7e]{%d,}"
_UTF16_RUN = rb"(?:[\x20-\x7e]\x00){%d,}"

DEFAULT_SCAN_BYTES = 64 * 1024 * 1024


def find_iocs(text: str, limit: int = 200) -> List[str]:
    """Return the unique indicators found in ``text``, in a stable order."""
    found: List[str] = []
    seen = set()
    for pattern in IOC_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0).rstrip(_TRAILING_PUNCTUATION)
            if value and value not in seen:
                seen.add(value)
                found.append(value)
                if len(found) >= limit:
                    return found
    return found


def is_ioc(text: str) -> bool:
    """True when ``text`` contains an indicator or a long base64 blob."""
    return any(pattern.search(text) for pattern in IOC_PATTERNS) or bool(BASE64_RE.search(text))


def iter_printable_strings(data: bytes, min_len: int = 6) -> Iterator[str]:
    """Yield printable ASCII and UTF-16LE runs from raw bytes (like `strings -el`)."""
    for match in re.finditer(_ASCII_RUN % min_len, data):
        yield match.group(0).decode("ascii")
    for match in re.finditer(_UTF16_RUN % min_len, data):
        yield match.group(0).decode("utf-16-le")


def scan_file_for_iocs(file_path: str, max_bytes: int = DEFAULT_SCAN_BYTES, limit: int = 200) -> List[str]:
    """Extract indicators straight from a file's bytes, without radare2."""
    with open(file_path, "rb") as handle:
        data = handle.read(max_bytes)

    found: List[str] = []
    seen = set()
    for candidate in iter_printable_strings(data):
        for value in find_iocs(candidate, limit=limit):
            if value not in seen:
                seen.add(value)
                found.append(value)
                if len(found) >= limit:
                    return found
    return found
