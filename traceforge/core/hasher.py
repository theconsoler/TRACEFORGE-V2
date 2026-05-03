"""
TraceForge v2 — Evidence Hasher
Computes SHA-256 hash of evidence files before any analysis begins.
Uses chunked reading to handle large files (memory dumps, disk images).
"""

import hashlib
from pathlib import Path
from loguru import logger


CHUNK_SIZE = 65536  # 64KB chunks


def compute_sha256(file_path: str | Path) -> tuple[str, int]:
    """
    Compute the SHA-256 hash of a file using chunked reading.
    Returns a tuple of (hex_digest, file_size_in_bytes).
    Raises FileNotFoundError if the file does not exist.
    Raises PermissionError if the file cannot be read.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    sha256 = hashlib.sha256()
    file_size = 0

    logger.info(f"Computing SHA-256 for: {path.name}")

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
            file_size += len(chunk)

    digest = sha256.hexdigest()
    logger.info(f"SHA-256: {digest} | Size: {file_size:,} bytes | File: {path.name}")

    return digest, file_size


def verify_hash(file_path: str | Path, expected_hash: str) -> bool:
    """
    Verify a file's current SHA-256 hash against an expected value.
    Returns True if the hash matches, False if the file has been modified.
    Used to verify evidence integrity at any point after initial recording.
    """
    path = Path(file_path)

    try:
        current_hash, _ = compute_sha256(path)
        match = current_hash.lower() == expected_hash.lower()

        if match:
            logger.info(f"Hash verified OK: {path.name}")
        else:
            logger.warning(
                f"HASH MISMATCH — evidence may be corrupted or modified: {path.name}"
            )
            logger.warning(f"Expected: {expected_hash}")
            logger.warning(f"Current:  {current_hash}")

        return match

    except FileNotFoundError:
        logger.error(f"Cannot verify — file not found: {file_path}")
        return False
