"""Mati — self-evolving threat intelligence for OpenClaw agents.

Mati sits between your agent and the LLM as an OpenAI-compatible proxy.
It intercepts requests, injects threat intelligence skills, logs
predictions, scores them against objective ground truth (CISA KEV,
exploit publications, EPSS changes), and evolves new skills from
failure patterns.

Unlike general-purpose agent evolution frameworks, Mati's reward signal
comes from reality — not from another LLM's opinion. A CVE either gets
exploited or it doesn't. That objective signal produces faster
convergence and more reliable skills.

Quick start:
    pip install mati-intel
    mati setup
    mati start
"""

__version__ = "0.1.0"
