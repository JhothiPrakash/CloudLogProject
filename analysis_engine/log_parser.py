"""Log parsing utilities for CloudLogProject.

This module turns raw log lines into structured dictionaries so downstream
analysis code can work with timestamps, levels, IP addresses, and messages
without having to repeatedly re-parse the original text.
"""

import re
import json
import os
import gzip


class LogParser:
    """Parse plain-text and gzipped log files into structured events."""

    def __init__(self):
        """Pre-compile the regular expressions used during parsing.

        Pre-compiling the patterns once is faster than recompiling them for
        every log line, which matters when processing large files.
        """
        # IPv4 pattern: matches four dot-separated octets.
        # This is intentionally practical rather than overly strict, because we
        # want to recognize common log output without rejecting useful lines.
        self.ip_regex = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        )

        # Log levels are captured as a named group so we can quickly identify
        # the severity keyword if it appears anywhere in the line.
        self.level_regex = re.compile(
            r"\b(?P<level>INFO|WARNING|ERROR|CRITICAL|DEBUG)\b",
            re.IGNORECASE,
        )

        # Timestamp pattern that covers common ISO-like and syslog-like formats.
        # Examples it can recognize:
        # - 2026-07-09 14:22:31
        # - 2026-07-09T14:22:31.123Z
        # - Jul  9 14:22:31
        self.timestamp_regex = re.compile(
            r"(?P<timestamp>"
            r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?"
            r"|"
            r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
            r")"
        )

    def parse_line(self, line: str) -> dict:
        """Parse a single log line into a normalized dictionary.

        The method looks for a timestamp, log level, and IP address first. Once
        those pieces are identified, it removes them from the line so the
        remaining text can be returned as the message body.
        """
        original_line = line.rstrip("\n")

        timestamp_match = self.timestamp_regex.search(original_line)
        level_match = self.level_regex.search(original_line)
        ip_match = self.ip_regex.search(original_line)

        timestamp = timestamp_match.group("timestamp") if timestamp_match else None
        level = level_match.group("level").upper() if level_match else None
        ip_address = ip_match.group(0) if ip_match else None

        # Build the message by removing the extracted fields from the original
        # line. This keeps the parser simple while preserving the descriptive
        # text that follows the structured metadata.
        message = original_line
        for match in (timestamp_match, level_match, ip_match):
            if match:
                message = message.replace(match.group(0), "", 1)

        # Remove common separators that often remain after metadata extraction.
        message = re.sub(r"^[\s\-\[\]\(\):|]+", "", message).strip()

        parsed_event = {
            "timestamp": timestamp,
            "level": level,
            "ip": ip_address,
            "message": message,
        }

        # Serializing the event here ensures the structure remains JSON-friendly
        # for downstream APIs, queues, or storage layers.
        json.dumps(parsed_event)
        return parsed_event

    def process_file(self, filepath: str) -> list:
        """Read a log file line by line and return structured events.

        Gzipped logs are opened with gzip.open in text mode, while regular files
        use the built-in open function. Each line is parsed independently so the
        caller can process large files without loading them all into memory at
        once.
        """
        events = []

        try:
            is_gzipped = filepath.endswith(".gz")
            open_file = gzip.open if is_gzipped else open
            mode = "rt" if is_gzipped else "r"

            # Use a context manager so the file handle is always released, even
            # if parsing fails partway through the file.
            with open_file(filepath, mode, encoding="utf-8", errors="replace") as file_handle:
                for line in file_handle:
                    if not line.strip():
                        continue
                    events.append(self.parse_line(line))

        except (OSError, gzip.BadGzipFile, UnicodeError) as exc:
            print(f"Failed to read log file '{filepath}': {exc}")

        return events
