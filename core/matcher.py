from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

from core.ir import IRFunction
from core.normalizer import SequenceNormalizer


@dataclass
class MatchResult:
    cve: str
    verdict: str  # "patched", "vulnerable", "inconclusive"
    pre_score: float
    post_score: float
    confidence: float


class PatchMatcher:
    def __init__(self, fingerprints_dir: Path):
        self.fingerprints: List[dict] = []
        for fp in fingerprints_dir.glob("*.yaml"):
            with open(fp, 'r') as f:
                data = yaml.safe_load(f)
                if data:
                    data['pre_patch']['ir_sequence'] = [(inst['mnemonic'], tuple(inst['op_types'])) for inst in data['pre_patch']['ir_sequence']]
                    data['post_patch']['ir_sequence'] = [(inst['mnemonic'], tuple(inst['op_types'])) for inst in data['post_patch']['ir_sequence']]
                    self.fingerprints.append(data)
        self.normalizer = SequenceNormalizer()

    def match(self, ir_function: IRFunction) -> Optional[MatchResult]:
        seq = self.normalizer.normalize(ir_function)
        best_result = None
        best_conf = 0.0
        for fp in self.fingerprints:
            pre_seq = fp['pre_patch']['ir_sequence']
            post_seq = fp['post_patch']['ir_sequence']
            threshold = fp['confidence_threshold']
            pre_score = self.normalizer.similarity(seq, pre_seq)
            post_score = self.normalizer.similarity(seq, post_seq)
            conf = max(pre_score, post_score)
            if conf > threshold and conf > best_conf:
                verdict = (
                    "patched" if post_score > threshold else
                    "vulnerable" if pre_score > threshold else
                    "inconclusive"
                )
                best_result = MatchResult(
                    cve=fp['cve'],
                    verdict=verdict,
                    pre_score=pre_score,
                    post_score=post_score,
                    confidence=conf
                )
                best_conf = conf
        return best_result