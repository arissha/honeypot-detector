from dataclasses import dataclass, asdict

CATEGORIES = ("network", "host")

# (upper bound in %, label) - first band whose bound is above the score wins
VERDICT_BANDS = (
    (25, "UNLIKELY a honeypot"),
    (50, "POSSIBLY a honeypot"),
    (75, "LIKELY a honeypot"),
    (101, "VERY LIKELY a honeypot"),
)


@dataclass
class Finding:
    """One result from one check. This is the contract between B, C and D."""

    check: str              # short name, e.g. "ssh_banner_cowrie"
    category: str           # "network" or "host"
    triggered: bool         # did the check see a honeypot indicator?
    weight: float           # how strong the indicator is, 0.0 - 1.0
    reason: str             # human-readable explanation
    confidence: float = 1.0  # how sure the check is about its own result, 0.0 - 1.0
    evidence: str = ""      # short, non-sensitive proof (e.g. matched banner text)

    def __post_init__(self):
        if self.category not in CATEGORIES:
            raise ValueError(f"category must be one of {CATEGORIES}, got {self.category!r}")
        self.weight = _clamp(self.weight)
        self.confidence = _clamp(self.confidence)

    @property
    def strength(self):
        """Contribution of this finding as a probability-like number."""
        return self.weight * self.confidence if self.triggered else 0.0


@dataclass
class ScoreResult:
    likelihood_pct: float
    verdict: str
    checks_run: int
    checks_triggered: int
    category_pct: dict      # likelihood using only that category's findings
    contributions: list     # triggered findings, strongest first (dicts)

    def to_dict(self):
        return asdict(self)


def _clamp(value, low=0.0, high=1.0):
    return max(low, min(high, float(value)))


def _noisy_or(findings):
    """Combine independent indicators: 1 - product of (1 - strength)."""
    miss = 1.0
    for f in findings:
        miss *= 1.0 - f.strength
    return 1.0 - miss


def verdict_for(pct):
    for upper, label in VERDICT_BANDS:
        if pct < upper:
            return label
    return VERDICT_BANDS[-1][1]


def calculate_score(findings):
    """Return a ScoreResult for a list of Finding objects."""
    triggered = sorted(
        (f for f in findings if f.triggered), key=lambda f: f.strength, reverse=True
    )

    pct = round(_noisy_or(triggered) * 100, 1)
    category_pct = {
        cat: round(_noisy_or([f for f in triggered if f.category == cat]) * 100, 1)
        for cat in CATEGORIES
    }

    contributions = [
        {
            "check": f.check,
            "category": f.category,
            "points": round(f.strength * 100, 1),
            "reason": f.reason,
            "evidence": f.evidence,
        }
        for f in triggered
    ]

    return ScoreResult(
        likelihood_pct=pct,
        verdict=verdict_for(pct),
        checks_run=len(findings),
        checks_triggered=len(triggered),
        category_pct=category_pct,
        contributions=contributions,
    )
