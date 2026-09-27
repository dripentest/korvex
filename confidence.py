from signatures import stack_kind


def score_stack(cookie_hits: list, header_hits: list) -> tuple[str, str]:
    all_hits = cookie_hits + header_hits
    if not all_hits:
        return "NONE", "no signals"

    kinds = {stack_kind(s) or s for s in all_hits}
    total_signals = len(all_hits)

    if len(kinds) > 1:
        return "LOW", f"conflicting signals: {', '.join(sorted(kinds))}"

    if total_signals >= 2:
        return "HIGH", f"{total_signals} independent signals"

    return "MEDIUM", "1 signal"
