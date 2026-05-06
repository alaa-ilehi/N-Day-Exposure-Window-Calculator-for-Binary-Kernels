from dataclasses import dataclass
from typing import List

from core.matcher import MatchResult


@dataclass
class ExposureSummary:
    total_checked: int
    vulnerable: List[str]
    patched: List[str]
    inconclusive: List[str]
    exposure_score: float
    risk_level: str


class ExposureCalculator:
    def __init__(self, results: List[MatchResult]):
        self.results = results

    def summary(self) -> ExposureSummary:
        total_checked = len(self.results)
        vulnerable = [r.cve for r in self.results if r.verdict == "vulnerable"]
        patched = [r.cve for r in self.results if r.verdict == "patched"]
        inconclusive = [r.cve for r in self.results if r.verdict == "inconclusive"]
        exposure_score = len(vulnerable) / total_checked if total_checked > 0 else 0.0
        if exposure_score >= 0.66:
            risk_level = "critical"
        elif exposure_score >= 0.33:
            risk_level = "high"
        elif any(inconclusive) and not vulnerable:
            risk_level = "medium"
        elif all(r.verdict == "inconclusive" for r in self.results):
            risk_level = "low"
        else:
            risk_level = "clean"
        return ExposureSummary(
            total_checked=total_checked,
            vulnerable=vulnerable,
            patched=patched,
            inconclusive=inconclusive,
            exposure_score=exposure_score,
            risk_level=risk_level
        )