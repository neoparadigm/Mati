"""Skill synthesiser — generates corrective skills from failure patterns.

This is where Mati learns. When the analyser identifies a pattern
(3+ failures with the same root cause), the synthesiser generates a
new skill that addresses the gap. The skill is saved to disk and
injected into future requests immediately.

Key difference from MetaClaw: MetaClaw uses an LLM to generate skills
from subjective failure trajectories. Mati generates skills from
*deterministic corrective signals* derived from objective ground truth.
The LLM is optional (for richer skill descriptions), not required.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import RootCause
from .skills import save_evolved_skill

logger = logging.getLogger("mati.synthesiser")

# Keyword maps for each root cause — used for skill retrieval matching
_ROOT_CAUSE_KEYWORDS: dict[str, list[str]] = {
    RootCause.EPSS_UNDERWEIGHT.value: [
        "epss", "exploitation", "probability", "priority", "escalate",
    ],
    RootCause.VENDOR_BLIND_SPOT.value: [
        "vendor", "watchlist", "product", "coverage", "blind spot",
    ],
    RootCause.EXPLOIT_LAG.value: [
        "exploit", "poc", "proof of concept", "github", "monitoring",
    ],
    RootCause.CORRELATION_MISS.value: [
        "correlation", "multiple signals", "combined risk", "escalate",
    ],
    RootCause.HISTORICAL_PATTERN.value: [
        "ivanti", "fortinet", "citrix", "palo alto", "solarwinds",
        "vendor risk", "historical", "rapid exploitation",
    ],
    RootCause.CONTEXT_MISS.value: [
        "unauthenticated", "remote code execution", "no user interaction",
        "attack complexity", "description", "keywords",
    ],
    RootCause.FALSE_ALARM_OVERREACTION.value: [
        "false alarm", "overreaction", "attack complexity",
        "authentication", "cvss", "false positive",
    ],
}


def synthesise_skills(
    analysis_report: dict[str, Any],
    skills_dir: str,
    current_precision: float = 0.0,
    max_skills: int = 2,
) -> list[dict[str, Any]]:
    """Generate corrective skills from failure patterns.

    Args:
        analysis_report: output from analyser.analyse_failures()
        skills_dir: directory to save evolved skills
        current_precision: current precision score (for tracking improvement)
        max_skills: maximum skills to generate per cycle

    Returns:
        list of generated skill metadata dicts
    """
    patterns = analysis_report.get("patterns", [])

    if not patterns:
        logger.info("No patterns to synthesise skills from")
        return []

    generated: list[dict[str, Any]] = []

    for pattern in patterns[:max_skills]:
        root_cause = pattern["root_cause"]
        count = pattern["count"]
        corrective = pattern["corrective_signal"]
        examples = pattern.get("examples", [])

        # Build skill name
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        name = f"evolved-{root_cause.lower().replace('_', '-')}-{date_str}"

        # Build evidence string from examples
        evidence_lines = []
        for ex in examples[:3]:
            evidence_lines.append(
                f"  - {ex['cve_id']}: assigned {ex['assigned_priority']}, "
                f"actual outcome {ex['actual_outcome']}"
            )
        evidence = (
            f"Generated from {count} prediction failures.\n"
            + "\n".join(evidence_lines)
        )

        # Get keywords for retrieval matching
        keywords = _ROOT_CAUSE_KEYWORDS.get(root_cause, ["threat", "priority"])

        # Save the skill
        path = save_evolved_skill(
            skills_dir=skills_dir,
            name=name,
            rule=corrective,
            root_cause=root_cause,
            evidence=evidence,
            keywords=keywords,
            failures_analysed=count,
            precision_before=current_precision,
        )

        skill_meta = {
            "name": name,
            "root_cause": root_cause,
            "failures_analysed": count,
            "corrective_rule": corrective,
            "precision_before": current_precision,
            "path": str(path),
            "created": datetime.now(timezone.utc).isoformat(),
        }
        generated.append(skill_meta)

        logger.info(
            "Synthesised skill '%s' from %d failures (root cause: %s)",
            name, count, root_cause,
        )

    return generated


def log_evolution(
    evolution_log_path: Path,
    generated_skills: list[dict[str, Any]],
) -> None:
    """Append evolution events to the evolution log."""
    evolution_log_path.parent.mkdir(parents=True, exist_ok=True)

    with open(evolution_log_path, "a", encoding="utf-8") as f:
        for skill in generated_skills:
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "skill_synthesised",
                **skill,
            }
            f.write(json.dumps(event) + "\n")

    logger.info("Logged %d evolution events", len(generated_skills))
