"""Federated multi-repo query helpers. Spec: SPEC_6 §2. Milestone: M9."""


def iter_all_indexes(store, limit):
    """Yield indexes across all repos, up to `limit`. Spec: SPEC_6 §2."""
    raise NotImplementedError("M9 — SPEC_6 §2")


def merge_ranked_results(per_repo, cap):
    """Merge and re-rank per-repo results, capped at `cap`. Spec: SPEC_6 §2."""
    raise NotImplementedError("M9 — SPEC_6 §2")
