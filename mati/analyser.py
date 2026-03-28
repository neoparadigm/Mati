"""Failure analyser — finds patterns in Mati's prediction errors.

When Mati is wrong, this module figures out *why*. It classifies
failures into root cause categories and groups them into patterns.
Patterns (3+ failures of the same type) are the input to skill
evolution.

This is the bridge between "Mati was wrong" and "Mati learns."
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from .models import FailureRecord, Priority, RootCause, Verdict

logger = logging.getLogger("mati.analyser")


def extract_failures(predictions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract all resolved predictions with MISS or BAD_MISS verdicts."""
    return [
        p for p in predictions
        if p.get("resolved")
        and p.get("verdict") in (Verdict.MISS.value, Verdict.BAD_MISS.value, Verdict.FALSE_ALARM.value)
    ]


def classify_root_cause(failure: dict[str, Any]) -> RootCause:
    """Classify a single failure into a root cause category.

    Uses heuristics based on the data available at prediction time vs
    what actually happened. This is deterministic — no LLM needed.
    """
    verdict = failure.get("verdict", "")
    reasoning = failure.get("reasoning", "").lower()
    assigned = failure.get("assigned_priority", "")

    # False alarm: P1 call that was wrong
    if verdict == Verdict.FALSE_ALARM.value:
        return RootCause.FALSE_ALARM_OVERREACTION

    # Extract context if available
    context = failure.get("context", {})
    epss = context.get("epss_score", 0) if isinstance(context, dict) else 0
    has_exploit = context.get("has_public_exploit", False) if isinstance(context, dict) else False

    # EPSS was high but priority was low
    if epss > 0.5 and assigned in ("P2", "P3", "P4"):
        return RootCause.EPSS_UNDERWEIGHT

    # No exploit at prediction time but one appeared shortly after
    actual = failure.get("actual_outcome", "")
    if actual == "exploit_available" and not has_exploit:
        return RootCause.EXPLOIT_LAG

    # Check if vendor wasn't in watchlist
    affects = context.get("affects_watchlist", True) if isinstance(context, dict) else True
    if not affects and actual in ("exploited_in_wild", "exploit_available"):
        return RootCause.VENDOR_BLIND_SPOT

    # Check for historical pattern keywords in reasoning
    vendor = context.get("vendor", "").lower() if isinstance(context, dict) else ""
    high_risk_vendors = {"ivanti", "fortinet", "citrix", "palo alto", "solarwinds"}
    if vendor and any(v in vendor for v in high_risk_vendors):
        return RootCause.HISTORICAL_PATTERN

    # Check for missed context clues
    if any(kw in reasoning for kw in ["unauthenticated", "remote code", "no user interaction"]):
        if assigned in ("P2", "P3", "P4"):
            return RootCause.CONTEXT_MISS

    return RootCause.UNKNOWN


def analyse_failures(
    predictions: list[dict[str, Any]],
    min_pattern_size: int = 3,
) -> dict[str, Any]:
    """Analyse all failures, classify root causes, identify patterns.

    Returns a structured analysis report with patterns suitable for
    skill evolution.
    """
    failures = extract_failures(predictions)

    if not failures:
        logger.info("No failures to analyse")
        return {"total_failures": 0, "patterns": [], "failures": []}

    # Classify each failure
    classified: list[dict[str, Any]] = []
    for f in failures:
        root_cause = classify_root_cause(f)
        classified.append({
            "prediction_id": f.get("id", ""),
            "cve_id": f.get("cve_id", ""),
            "assigned_priority": f.get("assigned_priority", ""),
            "verdict": f.get("verdict", ""),
            "root_cause": root_cause.value,
            "actual_outcome": f.get("actual_outcome", ""),
            "reasoning": f.get("reasoning", "")[:200],
        })

    # Group by root cause
    cause_counts = Counter(c["root_cause"] for c in classified)

    # Identify patterns (3+ failures of same type)
    patterns = []
    for cause, count in cause_counts.most_common():
        if count >= min_pattern_size:
            examples = [c for c in classified if c["root_cause"] == cause]
            corrective = _suggest_corrective_signal(cause, examples)
            patterns.append({
                "root_cause": cause,
                "count": count,
                "examples": examples[:5],  # cap at 5 examples
                "corrective_signal": corrective,
            })

    report = {
        "total_failures": len(classified),
        "by_root_cause": dict(cause_counts),
        "patterns": patterns,
        "failures": classified,
    }

    logger.info(
        "Failure analysis: %d failures, %d patterns found",
        len(classified),
        len(patterns),
    )
    return report


def _suggest_corrective_signal(
    cause: str,
    examples: list[dict[str, Any]],
) -> str:
    """Generate a deterministic corrective signal for a root cause.

    These are heuristic rules — no LLM needed. The corrective signal
    becomes the basis for the evolved skill's rule.
    """
    signals = {
        RootCause.EPSS_UNDERWEIGHT.value: (
            "When EPSS > 0.5 AND CVSS >= 7.0, escalate to at least P2. "
            "When EPSS > 0.7 AND CVSS >= 8.0, assign P1 even without public exploit."
        ),
        RootCause.VENDOR_BLIND_SPOT.value: (
            "Expand watchlist to include vendors appearing in missed predictions. "
            "Consider adding the following vendors based on failure analysis."
        ),
        RootCause.EXPLOIT_LAG.value: (
            "Increase exploit monitoring frequency for CVEs with CVSS >= 9.0. "
            "When CVSS >= 9.0 and no exploit exists, assign P2 minimum and re-check within 48h."
        ),
        RootCause.CORRELATION_MISS.value: (
            "When multiple signals exist for the same CVE (high CVSS + high EPSS, "
            "or CVE + scanning activity), the combined risk exceeds any single signal. "
            "Escalate by one priority level when 2+ risk signals co-occur."
        ),
        RootCause.HISTORICAL_PATTERN.value: (
            "Vendors with history of rapid exploitation (Ivanti, Fortinet, Citrix, "
            "Palo Alto, SolarWinds) should receive +1 priority escalation by default. "
            "A CVSS 7.5 for Ivanti is not the same risk as CVSS 7.5 for a niche product."
        ),
        RootCause.CONTEXT_MISS.value: (
            "CVE descriptions containing 'unauthenticated', 'remote code execution', "
            "or 'no user interaction required' indicate low attack complexity. "
            "Escalate by one priority level when these keywords are present."
        ),
        RootCause.FALSE_ALARM_OVERREACTION.value: (
            "High CVSS alone is not sufficient for P1. Check attack complexity, "
            "authentication requirements, and user interaction. CVSS 9.0+ with "
            "high attack complexity or required authentication should be P2, not P1."
        ),
    }
    return signals.get(cause, "Manual review required for this failure pattern.")


def save_analysis(data_dir: str, report: dict[str, Any]) -> Path:
    """Save failure analysis to disk."""
    from datetime import datetime, timezone
    path = Path(data_dir) / "scores" / f"failures-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Saved failure analysis: %s", path)
    return path
