"""Example: Run Mati with skill injection and prediction logging.

This starts the Mati proxy in the foreground. Point your OpenClaw
agent at http://127.0.0.1:30100/v1 and every request will be:
  1. Enhanced with threat intelligence skills
  2. Forwarded to your upstream LLM
  3. Scanned for priority predictions and logged

Prerequisites:
    pip install mati-intel
    mati setup  # or set env vars below
"""

import os

from mati.config import MatiConfig
from mati.proxy import MatiProxy

config = MatiConfig(
    # LLM backend — where Mati forwards requests
    llm_provider="openrouter",
    llm_api_base="https://openrouter.ai/api/v1",
    llm_api_key=os.getenv("MATI_LLM_API_KEY", ""),
    llm_model="openrouter/auto",

    # Proxy — where OpenClaw connects
    proxy_host="127.0.0.1",
    proxy_port=30100,

    # Skills
    skills_enabled=True,
    auto_evolve=True,

    # Evolution
    evolution_enabled=True,
    evolution_min_failures=3,
    evolution_max_skills_per_cycle=2,
)

if __name__ == "__main__":
    proxy = MatiProxy(config)
    proxy.run()
