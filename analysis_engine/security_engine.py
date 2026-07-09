"""Security analysis engine for CloudLogProject.

This module loads Sigma-style YAML rules and evaluates parsed log events against
those rules to produce a structured security report. The design is intentionally
simple and defensive so it can run safely in production workflows where rules or
log inputs may be imperfect.
"""

import os
import yaml
import json


# The rule directory is resolved relative to this file so the engine works even
# when the application is started from a different current working directory.
RULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../security/sigma_rules'))


class SecurityEngine:
    """Evaluate structured log events against local Sigma-style rules."""

    def __init__(self):
        """Initialize the engine and load all available rule files.

        The rules list is kept in memory so event evaluation can stay fast. Rule
        loading happens automatically during construction so callers do not need
        to remember a separate initialization step.
        """
        self.rules = []
        self.load_rules()

    def load_rules(self):
        """Load Sigma-style YAML rule files from the configured rules folder.

        This method is best-effort: it skips unreadable files, invalid YAML, and
        non-dictionary payloads instead of failing the entire engine. That keeps
        the platform operational even if one rule is broken.
        """
        self.rules = []

        try:
            if not os.path.isdir(RULES_DIR):
                return

            for root, _, files in os.walk(RULES_DIR):
                for filename in files:
                    if not filename.lower().endswith((".yml", ".yaml")):
                        continue

                    file_path = os.path.join(root, filename)
                    try:
                        with open(file_path, "r", encoding="utf-8") as file_handle:
                            rule = yaml.safe_load(file_handle)

                        if isinstance(rule, dict):
                            self.rules.append(rule)
                    except (OSError, yaml.YAMLError, UnicodeError):
                        # A single broken rule should not stop the rest of the
                        # rule set from loading.
                        continue
        except OSError:
            # The outer guard handles unexpected filesystem failures such as
            # permission issues or transient directory access problems.
            return

    def _extract_match_terms(self, rule):
        """Collect text fragments that should be matched against log events.

        Sigma rules in this project use a compact detection structure, usually
        with a 'keywords' list. This helper also checks a few other common field
        names so the engine can remain useful if the rule format grows later.
        """
        terms = []
        detection = rule.get("detection", {}) if isinstance(rule, dict) else {}

        if isinstance(detection, dict):
            for field_name in ("keywords", "patterns", "pattern", "selection"):
                value = detection.get(field_name)
                if isinstance(value, str):
                    terms.append(value)
                elif isinstance(value, list):
                    terms.extend(item for item in value if isinstance(item, str))
                elif isinstance(value, dict):
                    for nested_value in value.values():
                        if isinstance(nested_value, str):
                            terms.append(nested_value)
                        elif isinstance(nested_value, list):
                            terms.extend(item for item in nested_value if isinstance(item, str))

        # Remove duplicates while preserving order so the same keyword is not
        # evaluated repeatedly for a single event.
        unique_terms = []
        for term in terms:
            normalized = term.strip()
            if normalized and normalized not in unique_terms:
                unique_terms.append(normalized)

        return unique_terms

    def _event_search_text(self, event):
        """Build a lowercase text blob from an event for matching.

        Most rule checks in this project are message-centric, but some rules may
        also need to match against other event fields. Converting the whole event
        to text lets us inspect the message and supporting fields with one
        consistent search string.
        """
        if not isinstance(event, dict):
            return ""

        parts = []
        for value in event.values():
            if value is None:
                continue
            parts.append(str(value))

        return " ".join(parts).lower()

    def analyze_events(self, structured_events: list) -> dict:
        """Evaluate parsed events and build a security report.

        Each event is compared against every loaded rule. When a keyword from a
        rule appears in the event text, the engine creates an alert record and
        updates the report summary counters. The overall threat level increases
        only when higher-severity matches are detected.
        """
        report = {
            "threat_level": "LOW",
            "alerts_triggered": [],
            "summary": {
                "total_alerts": 0,
                "critical_alerts": 0,
                "high_alerts": 0,
                "suspicious_ips": [],
            },
        }

        suspicious_ip_set = set()
        highest_threat_rank = 0
        severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

        for event in structured_events:
            event_text = self._event_search_text(event)
            if not event_text:
                continue

            event_timestamp = event.get("timestamp") if isinstance(event, dict) else None
            source_ip = event.get("ip") if isinstance(event, dict) else None

            for rule in self.rules:
                if not isinstance(rule, dict):
                    continue

                match_terms = self._extract_match_terms(rule)
                if not match_terms:
                    continue

                matched_term = None
                for term in match_terms:
                    if term.lower() in event_text:
                        matched_term = term
                        break

                if matched_term is None:
                    continue

                severity = str(rule.get("severity", "LOW")).upper()
                title = rule.get("title", "Unnamed Rule")

                alert = {
                    "rule_title": title,
                    "severity": severity,
                    "timestamp": event_timestamp,
                    "source_ip": source_ip,
                    "matched_term": matched_term,
                }
                report["alerts_triggered"].append(alert)
                report["summary"]["total_alerts"] += 1

                if severity == "CRITICAL":
                    report["summary"]["critical_alerts"] += 1
                elif severity == "HIGH":
                    report["summary"]["high_alerts"] += 1

                if source_ip:
                    suspicious_ip_set.add(source_ip)

                severity_score = severity_rank.get(severity, 0)
                if severity_score > highest_threat_rank:
                    highest_threat_rank = severity_score

        if highest_threat_rank >= severity_rank["CRITICAL"]:
            report["threat_level"] = "CRITICAL"
        elif highest_threat_rank >= severity_rank["HIGH"]:
            report["threat_level"] = "HIGH"
        elif report["summary"]["total_alerts"] > 0:
            report["threat_level"] = "MEDIUM"

        report["summary"]["suspicious_ips"] = sorted(suspicious_ip_set)

        # Serialize the report once so any accidental non-JSON values are caught
        # immediately during development or test execution.
        json.dumps(report)
        return report
