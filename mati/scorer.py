"""Scorer — measures Mati's prediction accuracy against ground truth.

The scorer is the credibility engine. It answers: "How good is Mati at
predicting which threats matter?" Unlike MetaClaw's subjective PRM judge,
Mati's ground truth is objective and verifiable:

- Did the CVE get added to CISA KEV? (fact)
- Did a public exploit appear? (fact)
- Did the EPSS score jump significantly? (fact)

No LLM judge. No human annotation. Reality is the judge.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import MatiConfig
from .models import Outcome, Priority, Scorecard, Verdict

logger = logging.getLogger("mati.scorer")


def load_predictions(path: Path) -> list[dict[str, Any]]:
    """Load all predictions from the JSONL log."""
    if not path.exists():
        return []
    predictions = []
    for line in path.read_text(encoding="utf-8").strip().splitlines():
        if line.strip():
            predictions.append(json.loads(line))
    return predictions


def save_predictions(path: Path, predictions: list[dict[str, Any]]) -> None:
    """Write all predictions back to the JSONL log."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for p in predictions:
            f.write(json.dumps(p) + "\n")


def resolve_predictions(
    predictions: list[dict[str, Any]],
    kev_cves: set[str],
    exploit_cves: set[str],
    epss_changes: dict[str, float],
    resolution_days: int = 30,
) -> list[dict[str, Any]]:
    """Resolve unresolved predictions against ground truth.

    Args:
        predictions: all logged predictions
        kev_cves: set of CVE IDs added to CISA KEV
        exploit_cves: set of CVE IDs with new public exploits
        epss_changes: dict of CVE ID → current EPSS (compare to logged EPSS)
        resolution_days: days after which an unexploited CVE is marked "not exploited"
    """
    now = datetime.now(timezone.utc)
    resolved_count = 0

    for pred in predictions:
        if pred.get("resolved"):
            continue

        cve_id = pred["cve_id"]
        assigned = pred["assigned_priority"]
        pred_time = datetime.fromisoformat(pred["timestamp"].replace("Z", "+00:00"))
        age_days = (now - pred_time).days

        outcome = None
        verdict = None
        detail = ""

        # Check ground truth sources
        if cve_id in kev_cves:
            outcome = Outcome.EXPLOITED_IN_WILD.value
            if assigned in ("P1",):
                verdict = Verdict.CORRECT.value
                detail = f"Correctly flagged as {assigned} before KEV addition."
            elif assigned == "P2":
                verdict = Verdict.MISS.value
                detail = f"Assigned {assigned}, should have been P1. KEV added."
            else:
                verdict = Verdict.BAD_MISS.value
                detail = f"Assigned {assigned}, should have been P1. KEV added."

        elif cve_id in exploit_cves:
            outcome = Outcome.EXPLOIT_AVAILABLE.value
            if assigned in ("P1", "P2"):
                verdict = Verdict.CORRECT.value
                detail = f"Correctly flagged as {assigned}. Public exploit now available."
            else:
                verdict = Verdict.MISS.value
                detail = f"Assigned {assigned}, should have been P2+. Public exploit published."

        elif age_days >= resolution_days:
            outcome = Outcome.NOT_EXPLOITED.value
            if assigned == "P1":
                verdict = Verdict.FALSE_ALARM.value
                detail = f"Assigned P1 but not exploited after {age_days} days."
            else:
                verdict = Verdict.CORRECT.value
                detail = f"Correctly assigned {assigned}. Not exploited after {age_days} days."

        if outcome:
            pred["resolved"] = True
            pred["actual_outcome"] = outcome
            pred["outcome_date"] = now.isoformat()
            pred["verdict"] = verdict
            pred["verdict_detail"] = detail
            resolved_count += 1

    logger.info("Resolved %d predictions", resolved_count)
    return predictions


def calculate_scorecard(
    predictions: list[dict[str, Any]],
    period_days: int = 30,
) -> Scorecard:
    """Calculate accuracy metrics from resolved predictions."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=period_days)

    resolved = [
        p for p in predictions
        if p.get("resolved")
        and datetime.fromisoformat(p["timestamp"].replace("Z", "+00:00")) >= cutoff
    ]

    total_in_period = [
        p for p in predictions
        if datetime.fromisoformat(p["timestamp"].replace("Z", "+00:00")) >= cutoff
    ]

    if not resolved:
        return Scorecard(
            date=now.strftime("%Y-%m-%d"),
            period_days=period_days,
            total_predictions=len(total_in_period),
            resolved=0,
            precision=0.0,
            recall=0.0,
            avg_lead_time_days=0.0,
            priority_accuracy=0.0,
            miss_rate=0.0,
        )

    # Precision: true P1s / all P1 calls
    p1_calls = [p for p in resolved if p["assigned_priority"] == "P1"]
    true_p1 = [
        p for p in p1_calls
        if p.get("actual_outcome") in (
            Outcome.EXPLOITED_IN_WILD.value,
            Outcome.EXPLOIT_AVAILABLE.value,
        )
    ]
    precision = len(true_p1) / len(p1_calls) if p1_calls else 0.0

    # Recall: caught before KEV / total KEV additions
    kev_entries = [
        p for p in resolved
        if p.get("actual_outcome") == Outcome.EXPLOITED_IN_WILD.value
    ]
    caught_as_p1 = [p for p in kev_entries if p["assigned_priority"] == "P1"]
    recall = len(caught_as_p1) / len(kev_entries) if kev_entries else 0.0

    # Lead time: days between P1 assignment and KEV addition
    lead_times = []
    for p in caught_as_p1:
        pred_dt = datetime.fromisoformat(p["timestamp"].replace("Z", "+00:00"))
        outcome_dt = datetime.fromisoformat(p["outcome_date"].replace("Z", "+00:00"))
        lead_times.append((outcome_dt - pred_dt).days)
    avg_lead = sum(lead_times) / len(lead_times) if lead_times else 0.0

    # Priority accuracy: correct verdicts / total resolved
    correct = [
        p for p in resolved if p.get("verdict") == Verdict.CORRECT.value
    ]
    accuracy = len(correct) / len(resolved) if resolved else 0.0

    # Miss rate: P3/P4 misses on exploited CVEs
    exploited = [
        p for p in resolved
        if p.get("actual_outcome") in (
            Outcome.EXPLOITED_IN_WILD.value,
            Outcome.EXPLOIT_AVAILABLE.value,
        )
    ]
    bad_misses = [
        p for p in exploited
        if p["assigned_priority"] in ("P3", "P4")
    ]
    miss_rate = len(bad_misses) / len(exploited) if exploited else 0.0

    scorecard = Scorecard(
        date=now.strftime("%Y-%m-%d"),
        period_days=period_days,
        total_predictions=len(total_in_period),
        resolved=len(resolved),
        precision=round(precision, 3),
        recall=round(recall, 3),
        avg_lead_time_days=round(avg_lead, 1),
        priority_accuracy=round(accuracy, 3),
        miss_rate=round(miss_rate, 3),
    )
    logger.info(
        "Scorecard: precision=%.2f recall=%.2f lead_time=%.1fd accuracy=%.2f miss_rate=%.2f",
        scorecard.precision, scorecard.recall, scorecard.avg_lead_time_days,
        scorecard.priority_accuracy, scorecard.miss_rate,
    )
    return scorecard


def save_scorecard(scores_dir: Path, scorecard: Scorecard) -> Path:
    """Save a scorecard to disk."""
    scores_dir.mkdir(parents=True, exist_ok=True)
    path = scores_dir / f"scorecard-{scorecard.date}.json"
    from dataclasses import asdict
    path.write_text(json.dumps(asdict(scorecard), indent=2), encoding="utf-8")
    logger.info("Saved scorecard: %s", path)
    return path
