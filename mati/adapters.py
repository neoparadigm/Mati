from __future__ import annotations

"""Framework adapters for Mati.

Connect Mati's threat intelligence evolution engine to any agentic
framework. Each adapter wraps the scoring, analysis, and evolution
pipeline so enterprise teams can integrate in a few lines.

Supported frameworks:
    - OpenClaw (native proxy mode)
    - Azure AI Foundry / Copilot Studio
    - AWS Bedrock Agents
    - LangChain / LangGraph
    - Microsoft AutoGen / MAF
    - Any OpenAI-compatible API

Usage:
    from mati.adapters import LangChainAdapter
    adapter = LangChainAdapter()
    result = adapter.assess("CVE-2026-20963", cvss=9.8, epss=0.82)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import uuid

from .config import MatiConfig
from .models import Priority
from .skills import load_skills, retrieve_skills, format_skill_injection
from .scorer import load_predictions, save_predictions

logger = logging.getLogger("mati.adapters")


class MatiCore:
    """Base class for all framework adapters.

    Provides the threat intelligence pipeline independent of any
    specific agent framework. All adapters inherit from this.
    """

    def __init__(self, config: Optional[MatiConfig] = None) -> None:
        self.config = config or MatiConfig()
        self.config.ensure_dirs()
        self.skills = load_skills(self.config.skills_dir)
        logger.info("MatiCore initialised with %d skills", len(self.skills))

    def get_skill_context(self, query: str) -> str:
        """Retrieve relevant skills and format as injectable context.

        Returns a text block that can be prepended to any LLM system
        prompt, regardless of framework.
        """
        selected = retrieve_skills(self.skills, query, self.config.skills_top_k)
        return format_skill_injection(selected)

    def log_prediction(
        self,
        cve_id: str,
        priority: str,
        reasoning: str,
        cvss: float = 0.0,
        epss: float = 0.0,
        vendor: str = "",
        product: str = "",
        affects_clients: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Log a priority prediction for later scoring against ground truth."""
        prediction = {
            "id": f"pred-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cve_id": cve_id,
            "assigned_priority": priority,
            "reasoning": reasoning[:500],
            "context": {
                "cvss_score": cvss,
                "epss_score": epss,
                "vendor": vendor,
                "product": product,
                "affects_watchlist": bool(affects_clients),
                "clients_affected": affects_clients or [],
            },
            "resolved": False,
            "actual_outcome": None,
        }

        path = self.config.predictions_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(prediction) + "\n")

        logger.info("Logged prediction: %s -> %s", cve_id, priority)
        return prediction

    def get_scorecard(self, days: int = 30) -> dict[str, Any]:
        """Get current accuracy metrics."""
        from .scorer import calculate_scorecard
        from dataclasses import asdict
        predictions = load_predictions(self.config.predictions_path)
        scorecard = calculate_scorecard(predictions, period_days=days)
        return asdict(scorecard)

    def run_evolution(self) -> list[dict[str, Any]]:
        """Run one evolution cycle and return generated skills."""
        from .analyser import analyse_failures
        from .scorer import calculate_scorecard
        from .synthesiser import synthesise_skills, log_evolution

        predictions = load_predictions(self.config.predictions_path)
        if not predictions:
            return []

        report = analyse_failures(predictions, self.config.evolution_min_failures)
        if not report["patterns"]:
            return []

        scorecard = calculate_scorecard(predictions)
        generated = synthesise_skills(
            report,
            skills_dir=self.config.skills_dir,
            current_precision=scorecard.precision,
            max_skills=self.config.evolution_max_skills_per_cycle,
        )
        log_evolution(self.config.evolution_log_path, generated)
        self.skills = load_skills(self.config.skills_dir)
        return generated


# ─────────────────────────────────────────────────────────────────────
# OpenClaw (native proxy mode)
# ─────────────────────────────────────────────────────────────────────

class OpenClawAdapter(MatiCore):
    """Native OpenClaw integration via the Mati proxy.

    Usage:
        from mati.adapters import OpenClawAdapter
        adapter = OpenClawAdapter()
        adapter.start_proxy()  # starts on :30100

    Then configure OpenClaw to point at http://127.0.0.1:30100/v1
    """

    def start_proxy(self) -> None:
        from .proxy import MatiProxy
        proxy = MatiProxy(self.config)
        proxy.run()


# ─────────────────────────────────────────────────────────────────────
# LangChain / LangGraph
# ─────────────────────────────────────────────────────────────────────

class LangChainAdapter(MatiCore):
    """LangChain integration. Injects Mati skills into chain prompts.

    Usage:
        from mati.adapters import LangChainAdapter
        from langchain_openai import ChatOpenAI

        mati = LangChainAdapter()
        llm = ChatOpenAI(model="gpt-4o")

        # Get skill-enhanced system prompt
        skills = mati.get_skill_context("Assess CVE-2026-20963")
        response = llm.invoke([
            {"role": "system", "content": f"You are a threat analyst. {skills}"},
            {"role": "user", "content": "Assess CVE-2026-20963, CVSS 9.8, EPSS 0.82"}
        ])

        # Log the prediction
        mati.log_prediction("CVE-2026-20963", "P1", response.content, cvss=9.8, epss=0.82)
    """

    def as_tool(self) -> dict[str, Any]:
        """Return Mati as a LangChain-compatible tool definition."""
        return {
            "name": "mati_threat_assess",
            "description": (
                "Assess a CVE's priority using Mati's evolved threat intelligence. "
                "Input: CVE ID, CVSS score, EPSS score, vendor, product. "
                "Output: recommended priority (P1-P4) with reasoning."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE identifier"},
                    "cvss": {"type": "number", "description": "CVSS score 0-10"},
                    "epss": {"type": "number", "description": "EPSS score 0-1"},
                    "vendor": {"type": "string", "description": "Vendor name"},
                    "product": {"type": "string", "description": "Product name"},
                },
                "required": ["cve_id"],
            },
        }


# ─────────────────────────────────────────────────────────────────────
# Azure AI Foundry / Copilot Studio
# ─────────────────────────────────────────────────────────────────────

class AzureFoundryAdapter(MatiCore):
    """Azure AI Foundry / Copilot Studio integration.

    Usage:
        from mati.adapters import AzureFoundryAdapter
        from openai import AzureOpenAI

        mati = AzureFoundryAdapter()
        client = AzureOpenAI(
            azure_endpoint="https://your-resource.openai.azure.com",
            api_key="your-key",
            api_version="2024-12-01-preview"
        )

        skills = mati.get_skill_context("Assess CVE-2026-20963")
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": f"You are a SOC analyst. {skills}"},
                {"role": "user", "content": "Assess CVE-2026-20963"}
            ]
        )

        mati.log_prediction("CVE-2026-20963", "P1", response.choices[0].message.content)
    """

    def as_copilot_plugin(self) -> dict[str, Any]:
        """Return Mati as a Copilot Studio plugin manifest."""
        return {
            "schema_version": "v1",
            "name": "mati-threat-intelligence",
            "description": "Self-evolving threat intelligence powered by Mati",
            "functions": [
                {
                    "name": "assess_cve",
                    "description": "Assess CVE priority with evolved threat intelligence skills",
                    "parameters": {
                        "cve_id": {"type": "string", "required": True},
                        "cvss": {"type": "number"},
                        "epss": {"type": "number"},
                    },
                },
                {
                    "name": "get_scorecard",
                    "description": "Get Mati's current accuracy metrics",
                },
            ],
        }


# ─────────────────────────────────────────────────────────────────────
# AWS Bedrock Agents
# ─────────────────────────────────────────────────────────────────────

class BedrockAdapter(MatiCore):
    """AWS Bedrock Agents integration.

    Usage:
        import boto3
        from mati.adapters import BedrockAdapter

        mati = BedrockAdapter()
        bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

        skills = mati.get_skill_context("Assess CVE-2026-20963")
        response = bedrock.converse(
            modelId="anthropic.claude-sonnet-4-20250514",
            messages=[{"role": "user", "content": [{"text": "Assess CVE-2026-20963"}]}],
            system=[{"text": f"You are a SOC analyst. {skills}"}],
        )

        result = response["output"]["message"]["content"][0]["text"]
        mati.log_prediction("CVE-2026-20963", "P1", result, cvss=9.8, epss=0.82)
    """

    def as_action_group(self) -> dict[str, Any]:
        """Return Mati as a Bedrock Agent action group definition."""
        return {
            "actionGroupName": "MatiThreatIntelligence",
            "description": "Self-evolving threat intelligence powered by Mati",
            "apiSchema": {
                "payload": json.dumps({
                    "openapi": "3.0.0",
                    "paths": {
                        "/assess": {
                            "post": {
                                "summary": "Assess CVE priority",
                                "parameters": [
                                    {"name": "cve_id", "in": "query", "required": True, "schema": {"type": "string"}},
                                    {"name": "cvss", "in": "query", "schema": {"type": "number"}},
                                    {"name": "epss", "in": "query", "schema": {"type": "number"}},
                                ],
                            }
                        }
                    },
                }),
            },
        }


# ─────────────────────────────────────────────────────────────────────
# Microsoft AutoGen / Multi-Agent Framework (MAF)
# ─────────────────────────────────────────────────────────────────────

class AutoGenAdapter(MatiCore):
    """Microsoft AutoGen / MAF integration.

    Usage:
        from mati.adapters import AutoGenAdapter

        mati = AutoGenAdapter()

        # Use as a system message enhancer for any AutoGen agent
        base_prompt = "You are a security analyst."
        enhanced = mati.enhance_system_message(
            base_prompt,
            "Assess CVE-2026-20963 affecting Microsoft SharePoint"
        )

        # Use enhanced prompt in your AutoGen agent config
        agent_config = {
            "name": "threat_analyst",
            "system_message": enhanced,
            "llm_config": {"model": "gpt-4o"},
        }
    """

    def enhance_system_message(self, base_prompt: str, query: str) -> str:
        """Enhance any system prompt with relevant Mati skills."""
        skills = self.get_skill_context(query)
        return f"{base_prompt}\n{skills}"

    def as_autogen_tool(self) -> dict[str, Any]:
        """Return Mati as an AutoGen function calling tool."""
        return {
            "type": "function",
            "function": {
                "name": "mati_assess_threat",
                "description": "Assess a CVE using Mati's self-evolving threat intelligence",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "description": "CVE identifier"},
                        "cvss": {"type": "number", "description": "CVSS score"},
                        "epss": {"type": "number", "description": "EPSS score"},
                        "vendor": {"type": "string", "description": "Vendor name"},
                        "product": {"type": "string", "description": "Product name"},
                    },
                    "required": ["cve_id"],
                },
            },
        }


# ─────────────────────────────────────────────────────────────────────
# Generic OpenAI-compatible (works with anything)
# ─────────────────────────────────────────────────────────────────────

class GenericAdapter(MatiCore):
    """Generic adapter for any OpenAI-compatible API.

    Works with: OpenRouter, Ollama, LiteLLM, vLLM, Together AI,
    Groq, Fireworks, Mistral, Anthropic (via proxy), or any
    OpenAI-compatible endpoint.

    Usage:
        import openai
        from mati.adapters import GenericAdapter

        mati = GenericAdapter()
        client = openai.OpenAI(base_url="https://openrouter.ai/api/v1", api_key="sk-...")

        skills = mati.get_skill_context("Assess CVE-2026-20963")
        response = client.chat.completions.create(
            model="openrouter/auto",
            messages=[
                {"role": "system", "content": f"You are a threat analyst. {skills}"},
                {"role": "user", "content": "Assess CVE-2026-20963, CVSS 9.8"}
            ]
        )

        mati.log_prediction("CVE-2026-20963", "P1", response.choices[0].message.content)
    """
    pass


# ─────────────────────────────────────────────────────────────────────
# Quick-start helpers
# ─────────────────────────────────────────────────────────────────────

def get_adapter(framework: str = "generic") -> MatiCore:
    """Factory function to get the right adapter.

    Args:
        framework: one of "openclaw", "langchain", "azure", "bedrock",
                   "autogen", "generic"
    """
    adapters = {
        "openclaw": OpenClawAdapter,
        "langchain": LangChainAdapter,
        "azure": AzureFoundryAdapter,
        "foundry": AzureFoundryAdapter,
        "copilot": AzureFoundryAdapter,
        "bedrock": BedrockAdapter,
        "autogen": AutoGenAdapter,
        "maf": AutoGenAdapter,
        "generic": GenericAdapter,
    }
    cls = adapters.get(framework.lower(), GenericAdapter)
    return cls()
