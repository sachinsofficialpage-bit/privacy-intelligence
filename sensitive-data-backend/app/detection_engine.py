import re
from dataclasses import dataclass
from typing import Callable, List, Optional


@dataclass(frozen=True)
class Finding:
    type: str
    risk_level: str
    value: str
    start: int
    end: int
    reason: str


# These patterns are intentionally conservative and intended for a hackathon MVP.
PATTERNS = [
    ("API_KEY", "CRITICAL", re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"), "Credential/token pattern detected."),
    ("BEARER_TOKEN", "CRITICAL", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.I), "Bearer authentication token detected."),
    ("JWT_TOKEN", "CRITICAL", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "JWT-like token detected."),
    ("PASSWORD", "CRITICAL", re.compile(r"\b(?:password|passwd|pwd|secret)\s*[:=]\s*[\"']?[^\s,;\"']{4,}[\"']?", re.I), "Password/secret assignment detected."),
    ("EMAIL", "MEDIUM", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "Email address detected."),
    ("PHONE", "MEDIUM", re.compile(r"(?<!\d)(?:\+?91[\s.-]?)?[6-9]\d{4}[\s.-]?\d{5}(?!\d)|(?<!\d)\+?\d{1,3}[\s.-]?\d{3,4}[\s.-]?\d{4}(?!\d)"), "Phone-number-like pattern detected."),
    ("IP_ADDRESS", "MEDIUM", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "IPv4 address detected."),
    ("ID_NUMBER", "HIGH", re.compile(r"\b(?:[A-Z]{2,5}[- ]?\d{4,12}|\d{4}[- ]?\d{4}[- ]?\d{4})\b", re.I), "ID-like number detected."),
    ("FINANCIAL_NUMBER", "HIGH", re.compile(r"(?<!\d)(?:\d[ -]?){13,18}\d(?!\d)"), "Financial-number-like sequence detected."),
]


def _luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _is_probable_financial(value: str) -> bool:
    compact = re.sub(r"[ -]", "", value)
    return _luhn_ok(compact)


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def detect(text: str) -> List[Finding]:
    raw: List[Finding] = []
    for kind, risk, pattern, reason in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if kind == "FINANCIAL_NUMBER" and not _is_probable_financial(value):
                continue
            raw.append(Finding(kind, risk, value, match.start(), match.end(), reason))

    # Prefer the more specific/stronger finding when patterns overlap.
    priority = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    raw.sort(key=lambda f: (f.start, -priority[f.risk_level], -(f.end - f.start)))
    selected: List[Finding] = []
    for finding in raw:
        if any(_overlaps(finding.start, finding.end, existing.start, existing.end) for existing in selected):
            continue
        selected.append(finding)

    return sorted(selected, key=lambda f: f.start)


def exposure_score(findings: List[Finding]) -> int:
    weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    score = min(100, sum(weights.get(f.risk_level, 0) for f in findings))
    return score


def score_label(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"
