"""Master report orchestration for CloudLogProject.

This module coordinates the parser, security engine, search engine, and AI
engine into one linear workflow so callers can generate a complete incident
report with a single method call.
"""

import os
import json

from .log_parser import LogParser
from .security_engine import SecurityEngine
from .search_engine import LogSearchEngine
from .ai_engine import AIEngine


class ReportBuilder:
    """Build a complete security report from a raw log file."""

    def __init__(self):
        """Create all engine instances up front.

        Instantiating the engines once keeps the orchestration method simple and
        makes the report generation path easy to follow and test.
        """
        self.parser = LogParser()
        self.security = SecurityEngine()
        self.search = LogSearchEngine()
        self.ai = AIEngine()

    def generate_master_report(self, job_id: str, filepath: str) -> dict:
        """Run the full analysis pipeline and return one consolidated report.

        The pipeline is intentionally linear:
        1. Parse the raw file into structured events.
        2. Run the security engine to detect suspicious activity.
        3. Index the events so they can be searched later.
        4. Ask the AI engine for a root-cause investigation.
        5. Calculate a few operational statistics for quick summary views.
        6. Package everything into one report dictionary.
        """
        try:
            # Step 1: Convert the raw log file into structured event records.
            structured_events = self.parser.process_file(filepath)

            # Step 2: Evaluate the parsed events against local security rules.
            security_report = self.security.analyze_events(structured_events)

            # Step 3: Store the data in OpenSearch or the fallback in-memory store.
            self.search.index_logs(job_id, structured_events)

            # Step 4: Use the AI engine to produce a higher-level investigation.
            ai_report = self.ai.analyze_root_cause(security_report, structured_events)

            # Step 5: Calculate simple system-health statistics from the events.
            total_logs = len(structured_events)
            error_count = sum(
                1 for event in structured_events
                if str(event.get("level", "")).upper() == "ERROR"
            )
            warning_count = sum(
                1 for event in structured_events
                if str(event.get("level", "")).upper() == "WARNING"
            )
            unique_ips = {
                event.get("ip")
                for event in structured_events
                if isinstance(event, dict) and event.get("ip")
            }

            master_report = {
                "job_id": job_id,
                "status": "COMPLETED",
                "system_health": {
                    "total_logs": total_logs,
                    "error_count": error_count,
                    "warning_count": warning_count,
                    "unique_ips_count": len(unique_ips),
                },
                "security_analysis": security_report,
                "ai_investigation": ai_report,
            }

            # Serialize once to ensure the final report remains JSON-friendly for
            # API responses, file exports, or database storage.
            json.dumps(master_report)
            return master_report
        except Exception as exc:
            # Any failure in the orchestration layer should return a structured
            # error instead of breaking the caller's control flow.
            return {
                "job_id": job_id,
                "status": "FAILED",
                "error": f"Report generation failed for {os.path.basename(filepath)}: {exc}",
            }
