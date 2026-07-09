"""Job lifecycle management for CloudLogProject.

This module provides a small, production-oriented job manager that keeps track
of temporary per-job workspace folders and the initial metadata for each job.
The implementation is intentionally simple, but it avoids blocking patterns and
handles common operating-system failures defensively.
"""

import os
import datetime
import secrets
import json
import shutil
import logging


# TEMP_DIR is the root folder used for all job-specific temporary workspaces.
# It is resolved relative to this file so the module continues to work no matter
# where the application is launched from.
TEMP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../storage/temp'))


# Module-level logger used for cleanup and other operational diagnostics.
logger = logging.getLogger(__name__)


class JobManager:
    """Manage temporary job workspaces and job metadata.

    The class is deliberately lightweight so it can be used from web request
    handlers, worker processes, or background orchestration code without
    introducing unnecessary dependencies.
    """

    def __init__(self):
        """Create the job manager and ensure the temporary root exists.

        The temporary directory is created eagerly so later methods can assume
        the base path is available. This reduces the number of failure points in
        the rest of the workflow.
        """
        os.makedirs(TEMP_DIR, exist_ok=True)

    def generate_job_id(self):
        """Generate a unique, human-readable job identifier.

        The format is JOB-YYYYMMDD-XXXX where:
        - YYYYMMDD is the current calendar date.
        - XXXX is a securely generated 4-character uppercase hexadecimal token.

        Using a secure token lowers the chance of collisions when multiple jobs
        are created at nearly the same time.
        """
        current_date = datetime.datetime.now().strftime("%Y%m%d")
        token = secrets.token_hex(2).upper()
        return f"JOB-{current_date}-{token}"

    def initialize_workspace(self, job_id):
        """Create and return the dedicated workspace folder for a job.

        Each job gets its own subdirectory inside TEMP_DIR. Keeping job artifacts
        isolated prevents accidental overwrites and makes cleanup predictable.
        """
        workspace_path = os.path.join(TEMP_DIR, job_id)
        os.makedirs(workspace_path, exist_ok=True)
        return workspace_path

    def create_job_record(self, job_id, filename, log_type):
        """Build the initial in-memory record for a job.

        The returned dictionary is ready to be serialized to JSON or stored in a
        database. It captures the job identity, source file, detected log type,
        current status, creation time, and the state of each major processing
        step.
        """
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        job_record = {
            "job_id": job_id,
            "filename": filename,
            "log_type": log_type,
            "status": "PENDING",
            "created_at": created_at,
            "steps": {
                "parsing": "PENDING",
                "security_scan": "PENDING",
                "ai_analysis": "PENDING",
            },
        }

        # The record is serialized here as a safety check so any non-serializable
        # values are detected early during development and testing.
        json.dumps(job_record)
        return job_record

    def cleanup_workspace(self, job_id):
        """Remove a job workspace and all of its contents.

        This method is designed to be safe and resilient. It only attempts to
        delete the job-specific subdirectory inside TEMP_DIR, and it logs any
        operating-system errors instead of raising them into the caller unless a
        truly unexpected exception occurs.
        """
        workspace_path = os.path.join(TEMP_DIR, job_id)

        try:
            if os.path.isdir(workspace_path):
                shutil.rmtree(workspace_path)
                logger.info("Cleaned up job workspace: %s", workspace_path)
            else:
                logger.info("No workspace found to clean for job_id=%s", job_id)
        except OSError as exc:
            logger.error(
                "Failed to clean up job workspace '%s': %s",
                workspace_path,
                exc,
                exc_info=True,
            )
        except Exception as exc:
            logger.exception(
                "Unexpected error while cleaning workspace '%s': %s",
                workspace_path,
                exc,
            )
