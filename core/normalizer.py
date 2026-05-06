from typing import List, Tuple

from core.ir import IRFunction


class SequenceNormalizer:
    def normalize(self, ir_function: IRFunction) -> List[Tuple[str, Tuple[str, ...]]]:
        return [(inst.mnemonic, inst.op_types) for inst in ir_function.instructions]

    def similarity(self, seq_a: List[Tuple[str, Tuple[str, ...]]], seq_b: List[Tuple[str, Tuple[str, ...]]]) -> float:
        if not seq_a or not seq_b:
            return 0.0
        len_a, len_b = len(seq_a), len(seq_b)
        min_len = min(len_a, len_b)
        window = min(min_len, 20)
        if min_len < 6:
            return 0.0
        max_lcs = 0
        # Slide over b
        for i in range(max(0, len_b - window + 1)):
            sub_b = seq_b[i:i + window]
            lcs_len = self._lcs_length(seq_a, sub_b)
            max_lcs = max(max_lcs, lcs_len)
        # Slide over a if longer
        if len_a > len_b:
            for i in range(max(0, len_a - window + 1)):
                sub_a = seq_a[i:i + window]
                lcs_len = self._lcs_length(sub_a, seq_b)
                max_lcs = max(max_lcs, lcs_len)
        return max_lcs / min_len

    def _lcs_length(self, a: List[Tuple[str, Tuple[str, ...]]], b: List[Tuple[str, Tuple[str, ...]]]) -> int:
        m, n = len(a), len(b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if a[i - 1] == b[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        return dp[m][n]