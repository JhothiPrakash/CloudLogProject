"""
Cloud-Based Log Backup & Analytics - Uploader Script
Compresses .log files and uploads to S3 with idempotency tracking.
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
import gzip
import hashlib
import os

# ============== CONFIGURATION ==============
BUCKET_NAME = "cloud-log-project-jp"
REGION = "eu-north-1"
HASH_FILE = "hashes.txt"
LOG_FOLDER = "logs"
# ===========================================


def calculate_hash(file_path: str) -> str:
    """Returns SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def compress_file(file_path: str) -> str:
    """Compresses a .log file to .gz format and returns the new path."""
    gz_path = f"{file_path}.gz"
    with open(file_path, "rb") as src, gzip.open(gz_path, "wb") as dst:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            dst.write(chunk)
    return gz_path


def load_hashes() -> set:
    """Load existing hashes from the hash file (for idempotency)."""
    if not os.path.exists(HASH_FILE):
        return set()
    with open(HASH_FILE, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())


def save_hash(file_hash: str) -> None:
    """Append a new hash to the hash file."""
    with open(HASH_FILE, "a", encoding="utf-8") as f:
        f.write(f"{file_hash}\n")


def main():
    print("=" * 50)
    print("Cloud Log Uploader - Starting...")
    print(f"Bucket: {BUCKET_NAME} | Region: {REGION}")
    print("=" * 50)

    # Load existing hashes for idempotency check
    existing_hashes = load_hashes()
    print(f"Loaded {len(existing_hashes)} existing hashes from {HASH_FILE}")

    # Check if logs folder exists
    if not os.path.isdir(LOG_FOLDER):
        print(f"ERROR: Folder '{LOG_FOLDER}/' not found. Creating it...")
        os.makedirs(LOG_FOLDER)
        print(f"Created '{LOG_FOLDER}/' folder. Add .log files and run again.")
        return

    # Initialize S3 client
    try:
        s3 = boto3.client("s3", region_name=REGION)
    except Exception as e:
        print(f"ERROR: Failed to create S3 client: {e}")
        return

    # Process all .log files in the logs folder
    uploaded_count = 0
    skipped_count = 0

    for filename in os.listdir(LOG_FOLDER):
        if not filename.endswith(".log"):
            continue

        file_path = os.path.join(LOG_FOLDER, filename)
        
        # Skip if it's a directory
        if not os.path.isfile(file_path):
            continue

        print(f"\nProcessing: {filename}")

        # Calculate hash for idempotency
        try:
            file_hash = calculate_hash(file_path)
        except OSError as e:
            print(f"  ERROR: Failed to hash {filename}: {e}")
            continue

        # Check if already uploaded (idempotency)
        if file_hash in existing_hashes:
            print(f"  Skipping duplicate (hash already exists)")
            skipped_count += 1
            continue

        # Compress the file
        try:
            gz_path = compress_file(file_path)
            print(f"  Compressed to: {os.path.basename(gz_path)}")
        except OSError as e:
            print(f"  ERROR: Failed to compress {filename}: {e}")
            continue

        # Upload to S3
        s3_key = os.path.basename(gz_path)
        try:
            s3.upload_file(
                gz_path, 
                BUCKET_NAME, 
                s3_key,
                ExtraArgs={
                    "ContentType": "application/gzip",
                    "Metadata": {"sha256": file_hash}
                }
            )
            print(f"  Uploaded to S3: s3://{BUCKET_NAME}/{s3_key}")
            uploaded_count += 1

            # Save hash for idempotency
            save_hash(file_hash)
            existing_hashes.add(file_hash)

        except (BotoCoreError, ClientError) as e:
            print(f"  ERROR: Failed to upload {filename}: {e}")
            continue
        except Exception as e:
            print(f"  ERROR: Unexpected error uploading {filename}: {e}")
            continue
        finally:
            # Clean up the local .gz file
            if os.path.exists(gz_path):
                os.remove(gz_path)
                print(f"  Cleaned up local .gz file")

    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print(f"  Uploaded: {uploaded_count} file(s)")
    print(f"  Skipped (duplicates): {skipped_count} file(s)")
    print("=" * 50)


if __name__ == "__main__":
    main()
