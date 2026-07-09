"""AI-assisted root cause analysis for CloudLogProject.

This module talks to Google's Gemini API when an API key is available. If the
key is missing or the API call fails, the engine returns a safe structured
fallback instead of crashing the application.
"""

import os
import json

from google import genai


class AIEngine:
    """Run AI-assisted analysis on security reports and structured log events."""

    def __init__(self):
        """Initialize the Gemini client when credentials are available.

        The engine is intentionally tolerant of missing configuration. That way
        development, testing, and offline deployments can continue to function
        without a hard dependency on the external AI service.
        """
        api_key = os.getenv("GEMINI_API_KEY")
        self.enabled = bool(api_key)
        self.client = None

        if not api_key:
            return

        try:
            self.client = genai.Client(api_key=api_key)
        except Exception as exc:
            self.enabled = False
            self.client = None
            print(f"Warning: Gemini client initialization failed: {exc}")

    def _build_event_subset(self, structured_events):
        """Keep only the most relevant events to avoid large prompts.

        Large raw event streams can quickly exceed context limits. This helper
        selects the last 20 WARNING and ERROR events so the model receives the
        strongest signals without unnecessary noise.
        """
        relevant_events = []
        for event in structured_events:
            if not isinstance(event, dict):
                continue

            level = str(event.get("level", "")).upper()
            if level in {"ERROR", "WARNING"}:
                relevant_events.append(event)

        return relevant_events[-20:]

    def _extract_recommendations(self, ai_text):
        """Turn the model's free-form text into a small recommendation list.

        The Gemini response may return numbered items, bullet points, or a short
        paragraph. This parser tries to recover the three most useful action
        items while still preserving the original text for human review.
        """
        recommendations = []
        lines = [line.strip() for line in ai_text.splitlines() if line.strip()]

        for line in lines:
            cleaned = line.lstrip("-*•0123456789. ").strip()
            if cleaned and cleaned.lower() not in {"analysis", "recommendations"}:
                recommendations.append(cleaned)

        if not recommendations and ai_text.strip():
            recommendations.append(ai_text.strip())

        # Keep the result compact and actionable for dashboards or response APIs.
        return recommendations[:3]

    def analyze_root_cause(self, security_report: dict, structured_events: list) -> dict:
        """Ask Gemini to infer the likely root cause of a security incident.

        The method only sends the most relevant report fields and the last few
        high-signal events. This keeps the prompt small, reduces latency, and
        lowers the chance of exceeding model context limits.
        """
        if not self.enabled:
            return {
                "status": "skipped",
                "message": "Gemini API key not configured.",
                "analysis": "",
                "recommendations": [],
            }

        try:
            critical_report_data = {
                "threat_level": security_report.get("threat_level"),
                "alerts_triggered": security_report.get("alerts_triggered", []),
            }
            event_subset = self._build_event_subset(structured_events)

            # The prompt gives the model a clear role and a constrained task so
            # it can focus on root cause analysis rather than restating raw data.
            prompt_payload = {
                "role": "Cybersecurity Analyst",
                "instructions": [
                    "Identify the most likely root cause of the incident.",
                    "Use the provided threat summary and event sample only.",
                    "Return concise, operationally useful findings.",
                    "Provide exactly 3 bulleted recommendations.",
                ],
                "security_report": critical_report_data,
                "recent_events": event_subset,
            }
            prompt = (
                "You are a Cybersecurity Analyst reviewing a security incident. "
                "Analyze the following JSON payload and determine the most likely root cause. "
                "Then provide exactly 3 practical recommendations as bullet points.\n\n"
                f"{json.dumps(prompt_payload, indent=2, default=str)}"
            )

            # The model call is intentionally direct so the surrounding application
            # can treat the AI engine as a simple, synchronous analysis service.
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )

            ai_text = getattr(response, "text", "") or ""
            recommendations = self._extract_recommendations(ai_text)

            return {
                "status": "success",
                "analysis": ai_text,
                "recommendations": recommendations,
            }
        except Exception as exc:
            # Network failures, quota errors, and transient API issues should all
            # return a structured response so the rest of the system can continue.
            return {
                "status": "error",
                "message": f"Gemini analysis failed: {exc}",
                "analysis": "",
                "recommendations": [],
            }
