"""Mati command-line interface.

Usage:
    mati setup      — interactive configuration wizard
    mati start      — start the proxy (foreground)
    mati status     — show health and loaded skills
    mati score      — calculate and display accuracy scorecard
    mati evolve     — run one evolution cycle (analyse failures → synthesise skills)
    mati feeds      — test OSINT feed connectivity
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from .config import MatiConfig

MATI_CONFIG_PATH = Path.home() / ".mati" / "config.json"


def _load_config() -> MatiConfig:
    if MATI_CONFIG_PATH.exists():
        data = json.loads(MATI_CONFIG_PATH.read_text(encoding="utf-8"))
        return MatiConfig(**{
            k: v for k, v in data.items()
            if k in MatiConfig.__dataclass_fields__
        })
    return MatiConfig()


def _save_config(config: MatiConfig) -> None:
    MATI_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    from dataclasses import asdict
    data = asdict(config)
    MATI_CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


@click.group()
def cli() -> None:
    """Mati — self-evolving threat intelligence for OpenClaw agents."""
    pass


@cli.command()
def setup() -> None:
    """Interactive configuration wizard."""
    click.echo("\n🛡️  Mati Setup\n")

    config = _load_config()

    # LLM provider
    click.echo("Step 1: LLM Backend")
    click.echo("  Mati proxies requests to your LLM. Configure the upstream.")
    config.llm_api_base = click.prompt(
        "  LLM API base URL",
        default=config.llm_api_base,
    )
    config.llm_api_key = click.prompt(
        "  LLM API key",
        default=config.llm_api_key or "",
        hide_input=True,
        show_default=False,
    )
    config.llm_model = click.prompt(
        "  Default model",
        default=config.llm_model,
    )

    # Proxy
    click.echo("\nStep 2: Proxy")
    config.proxy_port = click.prompt(
        "  Proxy port",
        default=config.proxy_port,
        type=int,
    )

    # Agent framework
    click.echo("\nStep 3: Agent Framework")
    config.claw_type = click.prompt(
        "  Agent type (openclaw/copaw/ironclaw/none)",
        default=config.claw_type,
    )

    # OSINT API keys
    click.echo("\nStep 4: OSINT Feed API Keys (all optional, improves rate limits)")
    config.nvd_api_key = click.prompt(
        "  NIST NVD API key (free: nvd.nist.gov/developers/request-an-api-key)",
        default=config.nvd_api_key or "",
        show_default=False,
    )
    config.github_token = click.prompt(
        "  GitHub token (free: github.com/settings/tokens)",
        default=config.github_token or "",
        show_default=False,
    )
    config.shodan_api_key = click.prompt(
        "  Shodan API key (free: account.shodan.io)",
        default=config.shodan_api_key or "",
        show_default=False,
    )
    config.otx_api_key = click.prompt(
        "  AlienVault OTX API key (free: otx.alienvault.com)",
        default=config.otx_api_key or "",
        show_default=False,
    )

    # Evolution
    click.echo("\nStep 5: Evolution Engine")
    config.evolution_enabled = click.confirm(
        "  Enable skill evolution (recommended)",
        default=config.evolution_enabled,
    )

    # Save
    config.ensure_dirs()
    _save_config(config)

    click.echo(f"\n✅ Configuration saved to {MATI_CONFIG_PATH}")
    click.echo(f"   Data directory: {config.data_dir}")
    click.echo(f"   Skills directory: {config.skills_dir}")

    # Generate OpenClaw setup script
    if config.claw_type == "openclaw":
        script_path = Path.home() / ".mati" / "setup_openclaw.sh"
        script_content = _generate_openclaw_script(config)
        script_path.write_text(script_content, encoding="utf-8")
        script_path.chmod(0o755)
        click.echo(f"\n📝 OpenClaw setup script: {script_path}")
        click.echo(f"   Run: bash {script_path}")
        click.echo("   This configures OpenClaw to route through the Mati proxy.")

    click.echo("\n🚀 Next: run 'mati start' to launch the proxy.")


@cli.command()
def start() -> None:
    """Start the Mati proxy server."""
    config = _load_config()

    if not config.llm_api_key:
        click.echo("❌ No LLM API key configured. Run 'mati setup' first.")
        sys.exit(1)

    click.echo(f"\n🛡️  Mati proxy starting on {config.proxy_host}:{config.proxy_port}")
    click.echo(f"   Upstream: {config.llm_api_base}")
    click.echo(f"   Model: {config.llm_model}")
    click.echo(f"   Evolution: {'enabled' if config.evolution_enabled else 'disabled'}")
    click.echo()

    from .proxy import MatiProxy
    proxy = MatiProxy(config)
    proxy.run()


@cli.command()
def status() -> None:
    """Show Mati status and health."""
    config = _load_config()
    import httpx

    click.echo("\n🛡️  Mati Status\n")

    # Check proxy
    try:
        resp = httpx.get(
            f"http://{config.proxy_host}:{config.proxy_port}/health",
            timeout=5.0,
        )
        health = resp.json()
        click.echo(f"  Proxy:      ✅ running ({health['uptime_seconds']}s uptime)")
        click.echo(f"  Requests:   {health['requests_served']}")
        click.echo(f"  Skills:     {health['skills_loaded']} loaded")
        click.echo(f"  Evolution:  {'enabled' if health['evolution_enabled'] else 'disabled'}")
    except Exception:
        click.echo("  Proxy:      ❌ not running")

    # Check data
    pred_path = config.predictions_path
    if pred_path.exists():
        lines = pred_path.read_text(encoding="utf-8").strip().splitlines()
        resolved = sum(1 for l in lines if '"resolved": true' in l)
        click.echo(f"  Predictions: {len(lines)} total, {resolved} resolved")
    else:
        click.echo("  Predictions: no data yet")

    # Check skills
    from .skills import load_skills
    skills = load_skills(config.skills_dir)
    base = sum(1 for s in skills if s.get("_source") == "base")
    evolved = sum(1 for s in skills if s.get("_source") == "evolved")
    click.echo(f"  Skills:     {base} base, {evolved} evolved")

    click.echo()


@cli.command()
@click.option("--days", default=30, help="Period in days for scoring")
def score(days: int) -> None:
    """Calculate and display accuracy scorecard."""
    config = _load_config()

    from .scorer import calculate_scorecard, load_predictions, save_scorecard

    predictions = load_predictions(config.predictions_path)
    if not predictions:
        click.echo("❌ No predictions logged yet. Run Mati and make some threat assessments first.")
        sys.exit(1)

    scorecard = calculate_scorecard(predictions, period_days=days)
    save_scorecard(config.scores_dir, scorecard)

    click.echo(f"\n🛡️  Mati Scorecard ({days}-day period)\n")
    click.echo(f"  Predictions:     {scorecard.total_predictions}")
    click.echo(f"  Resolved:        {scorecard.resolved}")
    click.echo(f"  Precision:       {scorecard.precision:.1%}")
    click.echo(f"  Recall:          {scorecard.recall:.1%}")
    click.echo(f"  Avg lead time:   {scorecard.avg_lead_time_days:.1f} days")
    click.echo(f"  Priority acc:    {scorecard.priority_accuracy:.1%}")
    click.echo(f"  Miss rate:       {scorecard.miss_rate:.1%}")
    click.echo()


@cli.command()
def evolve() -> None:
    """Run one evolution cycle: analyse failures → synthesise skills."""
    config = _load_config()

    from .analyser import analyse_failures, save_analysis
    from .scorer import calculate_scorecard, load_predictions
    from .synthesiser import log_evolution, synthesise_skills

    predictions = load_predictions(config.predictions_path)
    if not predictions:
        click.echo("❌ No predictions to analyse.")
        sys.exit(1)

    # Analyse failures
    click.echo("🔍 Analysing failures...")
    report = analyse_failures(
        predictions,
        min_pattern_size=config.evolution_min_failures,
    )
    save_analysis(config.data_dir, report)

    click.echo(f"   Total failures: {report['total_failures']}")
    click.echo(f"   Patterns found: {len(report['patterns'])}")

    if not report["patterns"]:
        click.echo("   No patterns with enough failures to evolve from.")
        click.echo("   Need at least 3 failures of the same root cause.")
        return

    # Get current precision for tracking
    scorecard = calculate_scorecard(predictions)

    # Synthesise skills
    click.echo("\n🧬 Synthesising skills...")
    generated = synthesise_skills(
        report,
        skills_dir=config.skills_dir,
        current_precision=scorecard.precision,
        max_skills=config.evolution_max_skills_per_cycle,
    )

    log_evolution(config.evolution_log_path, generated)

    for skill in generated:
        click.echo(f"   ✅ {skill['name']}")
        click.echo(f"      Root cause: {skill['root_cause']}")
        click.echo(f"      Failures: {skill['failures_analysed']}")
        click.echo(f"      Rule: {skill['corrective_rule'][:80]}...")

    click.echo(f"\n🛡️  {len(generated)} skills evolved. They will be injected into the next request.")


@cli.command()
def feeds() -> None:
    """Test OSINT feed connectivity."""
    config = _load_config()

    click.echo("\n🛡️  Testing OSINT Feeds\n")

    async def _test():
        from . import feeds as f

        tests = [
            ("CISA KEV", f.fetch_cisa_kev(days=7)),
            ("CVEDB (Shodan)", f.fetch_cvedb_top(limit=5)),
            ("EPSS", f.fetch_epss(["CVE-2024-3400"])),
            ("GitHub Advisory", f.fetch_github_advisories(token=config.github_token, limit=3)),
            ("Shodan InternetDB", f.fetch_shodan_internetdb("8.8.8.8")),
            (("ThreatFox (key required)", f.fetch_threatfox_iocs(api_key=config.otx_api_key, days=1)),
        ]

        for name, coro in tests:
            try:
                result = await coro
                if isinstance(result, dict):
                    count = len(result)
                elif isinstance(result, list):
                    count = len(result)
                else:
                    count = 1
                click.echo(f"  ✅ {name:.<30} {count} results")
            except Exception as exc:
                click.echo(f"  ❌ {name:.<30} {exc}")

    asyncio.run(_test())
    click.echo()


def _generate_openclaw_script(config: MatiConfig) -> str:
    """Generate a shell script that configures OpenClaw to use Mati proxy."""
    return f"""#!/bin/bash
# Mati — Configure OpenClaw to route through the Mati threat intelligence proxy.
#
# This script modifies your OpenClaw config to point at the Mati proxy
# instead of directly at the LLM. Mati intercepts requests, injects
# threat intelligence skills, logs predictions, and forwards to the
# real LLM transparently.
#
# Usage: bash ~/.mati/setup_openclaw.sh

set -e

OPENCLAW_CONFIG="$HOME/.openclaw/openclaw.json"

if [ ! -f "$OPENCLAW_CONFIG" ]; then
    echo "❌ OpenClaw config not found at $OPENCLAW_CONFIG"
    echo "   Install and configure OpenClaw first."
    exit 1
fi

echo "🛡️  Configuring OpenClaw to route through Mati proxy..."
echo "   Proxy: http://{config.proxy_host}:{config.proxy_port}/v1"

# Backup current config
cp "$OPENCLAW_CONFIG" "$OPENCLAW_CONFIG.pre-mati.bak"
echo "   Backup: $OPENCLAW_CONFIG.pre-mati.bak"

# Use openclaw configure to set the model endpoint
# This points OpenClaw at Mati's proxy instead of directly at the LLM
openclaw configure set agents.defaults.model.primary "openrouter/auto" 2>/dev/null || true

echo ""
echo "⚠️  Manual step required:"
echo "   Edit $OPENCLAW_CONFIG and update the OpenRouter base URL to:"
echo "   http://{config.proxy_host}:{config.proxy_port}/v1"
echo ""
echo "   Then restart OpenClaw:"
echo "   openclaw gateway stop && openclaw gateway start"
echo ""
echo "✅ Mati proxy will intercept all agent requests."
echo "   Run 'mati start' in a separate terminal first."
"""


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
