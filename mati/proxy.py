"""Mati proxy server.

An OpenAI-compatible API proxy that sits between OpenClaw (or any
OpenAI-compatible client) and the upstream LLM. On every request it:

1. Retrieves relevant threat intelligence skills
2. Injects them into the system prompt
3. Forwards the enhanced request to the real LLM
4. Captures the response for prediction logging
5. Returns the response transparently

The agent doesn't know Mati exists. It thinks it's talking directly
to the LLM.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

from .config import MatiConfig
from .skills import format_skill_injection, load_skills, retrieve_skills

logger = logging.getLogger("mati.proxy")

MATI_SYSTEM_PREAMBLE = (
    "You are enhanced by Mati, a threat intelligence layer that continuously "
    "learns from real-world security data. When assessing CVEs, vulnerabilities, "
    "or security findings, apply the threat intelligence skills injected below. "
    "Log your priority reasoning clearly so it can be scored against ground truth."
)


class MatiProxy:
    """OpenAI-compatible proxy with threat intelligence skill injection."""

    def __init__(self, config: MatiConfig) -> None:
        self.config = config
        self.app = FastAPI(title="Mati Threat Intelligence Proxy")
        self.skills: list[dict[str, Any]] = []
        self.request_count = 0
        self.start_time = time.time()

        self._register_routes()

    def _register_routes(self) -> None:
        self.app.get("/health")(self._health)
        self.app.get("/v1/models")(self._models)
        self.app.post("/v1/chat/completions")(self._chat_completions)

    async def _health(self) -> dict[str, Any]:
        uptime = int(time.time() - self.start_time)
        return {
            "status": "ok",
            "service": "mati",
            "uptime_seconds": uptime,
            "requests_served": self.request_count,
            "skills_loaded": len(self.skills),
            "evolution_enabled": self.config.evolution_enabled,
        }

    async def _models(self) -> dict[str, Any]:
        return {
            "object": "list",
            "data": [
                {
                    "id": self.config.llm_model,
                    "object": "model",
                    "owned_by": "mati-proxy",
                }
            ],
        }

    async def _chat_completions(self, request: Request) -> Any:
        body = await request.json()
        self.request_count += 1

        messages = body.get("messages", [])
        stream = body.get("stream", False)

        # --- Skill injection ---
        if self.config.skills_enabled and self.skills:
            query = self._extract_query(messages)
            selected = retrieve_skills(self.skills, query, self.config.skills_top_k)

            if selected:
                skill_block = format_skill_injection(selected)
                messages = self._inject_into_system(messages, skill_block)
                body["messages"] = messages
                logger.info(
                    "Injected %d skills into request #%d",
                    len(selected),
                    self.request_count,
                )

        # --- Forward to upstream LLM ---
        upstream_url = f"{self.config.llm_api_base}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.llm_api_key}",
        }

        # Override model to the configured upstream model
        body["model"] = self.config.llm_model

        if stream:
            return await self._stream_response(upstream_url, headers, body)
        else:
            return await self._sync_response(upstream_url, headers, body)

    async def _sync_response(
        self,
        url: str,
        headers: dict[str, str],
        body: dict[str, Any],
    ) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()

        data = resp.json()

        # --- Log prediction if this looks like a threat assessment ---
        self._maybe_log_prediction(body, data)

        return data

    async def _stream_response(
        self,
        url: str,
        headers: dict[str, str],
        body: dict[str, Any],
    ) -> StreamingResponse:
        async def generate():
            async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
                async with client.stream(
                    "POST", url, json=body, headers=headers
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )

    def _extract_query(self, messages: list[dict[str, Any]]) -> str:
        """Extract the user's latest message as a skill retrieval query."""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    return content[:500]
                if isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            return part.get("text", "")[:500]
        return ""

    def _inject_into_system(
        self,
        messages: list[dict[str, Any]],
        skill_block: str,
    ) -> list[dict[str, Any]]:
        """Inject skill block into the system message."""
        messages = [m.copy() for m in messages]

        injection = f"\n\n{MATI_SYSTEM_PREAMBLE}\n{skill_block}"

        # Find existing system message and append
        for msg in messages:
            if msg.get("role") == "system":
                msg["content"] = msg.get("content", "") + injection
                return messages

        # No system message — prepend one
        messages.insert(0, {"role": "system", "content": injection.strip()})
        return messages

    def _maybe_log_prediction(
        self,
        request_body: dict[str, Any],
        response_data: dict[str, Any],
    ) -> None:
        """Detect and log threat priority predictions from the response.

        Looks for priority assignments (P1, P2, P3, P4) and CVE IDs in
        the response text. This is heuristic — it catches most briefing
        responses without requiring the agent to use a structured format.
        """
        try:
            content = (
                response_data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
            )
        except (IndexError, AttributeError):
            return

        if not content:
            return

        import re
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
        priority_pattern = re.compile(r"\b(P1|P2|P3|P4)\b")

        cves_found = cve_pattern.findall(content)
        priorities_found = priority_pattern.findall(content)

        if not cves_found or not priorities_found:
            return

        # Log each CVE-priority pair
        predictions_path = self.config.predictions_path
        predictions_path.parent.mkdir(parents=True, exist_ok=True)

        for cve_id in set(cves_found):
            # Use the first priority mentioned near this CVE as a heuristic
            priority = priorities_found[0] if priorities_found else "P3"

            prediction = {
                "id": f"pred-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "cve_id": cve_id,
                "assigned_priority": priority,
                "reasoning": content[:500],
                "resolved": False,
                "actual_outcome": None,
            }

            with open(predictions_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(prediction) + "\n")

            logger.info("Logged prediction: %s → %s", cve_id, priority)

    def reload_skills(self) -> None:
        """Reload skills from disk."""
        self.skills = load_skills(self.config.skills_dir)

    def run(self) -> None:
        """Start the proxy server."""
        self.config.ensure_dirs()
        self.reload_skills()

        logger.info(
            "Mati proxy starting on %s:%d → %s",
            self.config.proxy_host,
            self.config.proxy_port,
            self.config.llm_api_base,
        )
        logger.info("Skills: %d loaded, evolution: %s", len(self.skills), self.config.evolution_enabled)

        uvicorn.run(
            self.app,
            host=self.config.proxy_host,
            port=self.config.proxy_port,
            log_level=self.config.log_level.lower(),
        )
