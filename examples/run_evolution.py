"""Example: Run a full evolution cycle.

This script demonstrates the complete evolution pipeline:
  1. Load predictions
  2. Fetch ground truth (CISA KEV, exploit publications)
  3. Resolve predictions against ground truth
  4. Score accuracy
  5. Analyse failures
  6. Synthesise corrective skills

Run this periodically (weekly recommended) or via cron.
"""

import asyncio
import json

from mati.analyser import analyse_failures, save_analysis
from mati.config import MatiConfig
from mati.feeds import fetch_cisa_kev, fetch_github_exploits
from mati.scorer import (
    calculate_scorecard,
    load_predictions,
    resolve_predictions,
    save_predictions,
    save_scorecard,
)
from mati.synthesiser import log_evolution, synthesise_skills


async def run_evolution_cycle() -> None:
    config = MatiConfig()
    config.ensure_dirs()

    print("🛡️  Mati Evolution Cycle\n")

    # Step 1: Load predictions
    predictions = load_predictions(config.predictions_path)
    print(f"  1. Loaded {len(predictions)} predictions")

    if not predictions:
        print("  ❌ No predictions to process. Run Mati and assess some threats first.")
        return

    # Step 2: Fetch ground truth
    print("  2. Fetching ground truth...")
    kev_entries = await fetch_cisa_kev(days=30)
    kev_cves = {e["cveID"] for e in kev_entries}
    print(f"     CISA KEV: {len(kev_cves)} entries in last 30 days")

    # Check for exploits on unresolved CVEs
    unresolved_cves = [
        p["cve_id"] for p in predictions if not p.get("resolved")
    ]
    exploit_cves: set[str] = set()
    for cve_id in unresolved_cves[:10]:  # limit to avoid rate limiting
        exploits = await fetch_github_exploits(cve_id, token=config.github_token)
        if exploits:
            exploit_cves.add(cve_id)
    print(f"     Exploits found: {len(exploit_cves)} CVEs with public PoC")

    # Step 3: Resolve predictions
    print("  3. Resolving predictions against ground truth...")
    predictions = resolve_predictions(
        predictions,
        kev_cves=kev_cves,
        exploit_cves=exploit_cves,
        epss_changes={},
        resolution_days=config.scoring_resolution_days,
    )
    save_predictions(config.predictions_path, predictions)

    resolved = [p for p in predictions if p.get("resolved")]
    print(f"     {len(resolved)} predictions now resolved")

    # Step 4: Score
    print("  4. Calculating scorecard...")
    scorecard = calculate_scorecard(predictions)
    save_scorecard(config.scores_dir, scorecard)
    print(f"     Precision:  {scorecard.precision:.1%}")
    print(f"     Recall:     {scorecard.recall:.1%}")
    print(f"     Lead time:  {scorecard.avg_lead_time_days:.1f} days")
    print(f"     Miss rate:  {scorecard.miss_rate:.1%}")

    # Step 5: Analyse failures
    print("  5. Analysing failures...")
    report = analyse_failures(predictions, min_pattern_size=config.evolution_min_failures)
    save_analysis(config.data_dir, report)
    print(f"     Failures: {report['total_failures']}")
    print(f"     Patterns: {len(report['patterns'])}")

    # Step 6: Synthesise skills
    if report["patterns"]:
        print("  6. Synthesising corrective skills...")
        generated = synthesise_skills(
            report,
            skills_dir=config.skills_dir,
            current_precision=scorecard.precision,
            max_skills=config.evolution_max_skills_per_cycle,
        )
        log_evolution(config.evolution_log_path, generated)

        for skill in generated:
            print(f"     ✅ {skill['name']} ({skill['root_cause']})")
        print(f"\n  🧬 {len(generated)} skills evolved.")
    else:
        print("  6. No patterns found — skipping skill synthesis.")
        print("     Need 3+ failures of the same root cause to evolve.")

    print("\n✅ Evolution cycle complete.")


if __name__ == "__main__":
    asyncio.run(run_evolution_cycle())
