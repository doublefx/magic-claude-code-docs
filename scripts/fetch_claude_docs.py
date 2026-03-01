#!/usr/bin/env python3
"""
Claude Code documentation fetcher.

Discovers pages from llms.txt (a standardized documentation index),
downloads markdown content, validates it, and tracks changes via
SHA-256 hashes in a manifest file.
"""

import hashlib
import json
import logging
import os
import random
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests


class FetchError(Exception):
    """Raised when documentation fetching fails."""


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Documentation index URL (replaces sitemap XML discovery)
LLMS_TXT_URL = "https://code.claude.com/docs/llms.txt"

# Hierarchical docs map — fetched as a bonus navigable reference
DOCS_MAP_URL = "https://code.claude.com/docs/en/claude_code_docs_map.md"

MANIFEST_FILE = "docs_manifest.json"

# Headers to bypass caching and identify the script
HEADERS = {
    "User-Agent": "Claude-Code-Docs-Fetcher/4.0",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 2  # initial delay in seconds
MAX_RETRY_DELAY = 30  # maximum delay in seconds
RATE_LIMIT_DELAY = 0.5  # seconds between requests
MAX_REDIRECTS = 5
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB

# Allowed hosts for redirect validation (SSRF prevention)
ALLOWED_HOSTS = frozenset(
    {
        "docs.anthropic.com",
        "code.claude.com",
        "anthropic.com",
        "raw.githubusercontent.com",
        "github.com",
    }
)


def safe_get(session: requests.Session, url: str, **kwargs) -> requests.Response:
    """GET with redirect validation against ALLOWED_HOSTS to prevent SSRF."""
    kwargs["allow_redirects"] = False
    kwargs["verify"] = True  # Never allow TLS bypass
    current_url = url
    for _ in range(MAX_REDIRECTS):
        parsed = urlparse(current_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Request with disallowed scheme: {parsed.scheme}")
        if parsed.hostname not in ALLOWED_HOSTS:
            raise ValueError(f"Request to disallowed host: {parsed.hostname}")
        response = session.get(current_url, **kwargs)
        if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            if not location:
                raise ValueError("Redirect with no Location header")
            # Resolve all redirect forms (absolute, path-absolute, relative)
            current_url = urljoin(current_url, location)
            continue
        return response
    raise ValueError(f"Too many redirects (>{MAX_REDIRECTS})")


def load_manifest(docs_dir: Path) -> dict:
    """Load the manifest of previously fetched files."""
    manifest_path = docs_dir / MANIFEST_FILE
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
            # Ensure required keys exist
            if "files" not in manifest:
                manifest["files"] = {}
            return manifest
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Failed to load manifest: {e}")
    return {"files": {}, "last_updated": None}


def save_manifest(docs_dir: Path, manifest: dict) -> None:
    """Save the manifest of fetched files.

    Creates a new dict with metadata fields added so the caller's dict is not mutated.
    """
    manifest_path = docs_dir / MANIFEST_FILE

    # Get GitHub repository from environment or use default
    github_repo = os.environ.get("GITHUB_REPOSITORY", "doublefx/claude-code-docs")
    github_ref = os.environ.get("GITHUB_REF_NAME", "main")

    # Validate repository name format (owner/repo)
    if not re.match(r"^[\w.-]+/[\w.-]+$", github_repo):
        logger.warning(f"Invalid repository format: {github_repo}, using default")
        github_repo = "doublefx/claude-code-docs"

    # Validate branch/ref name
    if not re.match(r"^[\w.-]+$", github_ref):
        logger.warning(f"Invalid ref format: {github_ref}, using default")
        github_ref = "main"

    output = {
        **manifest,
        "last_updated": datetime.now().isoformat(),
        "base_url": f"https://raw.githubusercontent.com/{github_repo}/{github_ref}/plugin/docs/",
        "github_repository": github_repo,
        "github_ref": github_ref,
        "description": "Claude Code documentation manifest. Keys are filenames, append to base_url for full URL.",
    }
    manifest_path.write_text(json.dumps(output, indent=2))


def url_to_safe_filename(url: str) -> str:
    """Convert a full documentation URL to a safe local filename.

    All URLs follow https://code.claude.com/docs/en/{name}.md, so we extract
    the last path segment directly.
    """
    parsed = urlparse(url)
    # Extract last path segment (e.g. "agent-teams.md")
    path = parsed.path.rstrip("/")
    filename = path.rsplit("/", 1)[-1] if "/" in path else path

    # Iteratively strip traversal sequences until stable
    prev = None
    while filename != prev:
        prev = filename
        filename = filename.replace("..", "").replace("/", "").replace("\\", "")
    filename = filename.lstrip(".")

    # Ensure .md extension
    if not filename.endswith(".md"):
        filename += ".md"

    # Reject empty or invalid results
    if not filename or filename == ".md":
        raise ValueError(f"Could not derive safe filename from URL: {url}")

    return filename


def discover_pages_from_llms_txt(session: requests.Session) -> list[tuple[str, str]]:
    """Discover documentation pages by parsing llms.txt.

    llms.txt contains markdown-formatted links like:
        - [Page Title](https://code.claude.com/docs/en/page-name.md)

    Returns:
        List of (title, url) tuples.

    Raises:
        RuntimeError: If llms.txt cannot be fetched or contains no links.
    """
    logger.info(f"Fetching documentation index: {LLMS_TXT_URL}")
    response = safe_get(session, LLMS_TXT_URL, headers=HEADERS, timeout=30)
    response.raise_for_status()

    content = response.text[:MAX_RESPONSE_SIZE]
    if len(content.strip()) < 50:
        raise RuntimeError(f"llms.txt content too short ({len(content)} bytes)")

    # Parse markdown links pointing to .md files under docs/en/
    pattern = r"\[([^\]]+)\]\((https://code\.claude\.com/docs/en/[^\)]+\.md)\)"
    matches = re.findall(pattern, content)

    if not matches:
        raise RuntimeError("No documentation links found in llms.txt")

    # Deduplicate by URL while preserving order
    seen: set[str] = set()
    pages: list[tuple[str, str]] = []
    for title, url in matches:
        if url not in seen:
            seen.add(url)
            pages.append((title, url))

    logger.info(f"Discovered {len(pages)} documentation pages from llms.txt")
    return pages


def validate_markdown_content(content: str, filename: str) -> None:
    """
    Validate that content is proper markdown.
    Raises ValueError if validation fails.
    """
    # Check for HTML content
    if not content or content.startswith("<!DOCTYPE") or "<html" in content[:100]:
        raise ValueError("Received HTML instead of markdown")

    # Check minimum length
    if len(content.strip()) < 50:
        raise ValueError(f"Content too short ({len(content)} bytes)")

    # Check for common markdown elements
    lines = content.split("\n")
    markdown_indicators = [
        "# ",  # Headers
        "## ",
        "### ",
        "```",  # Code blocks
        "- ",  # Lists
        "* ",
        "1. ",
        "[",  # Links
        "**",  # Bold
        "_",  # Italic
        "> ",  # Quotes
    ]

    # Count markdown indicators (stop early once threshold met)
    indicator_count = 0
    threshold = 3
    for line in lines[:50]:  # Check first 50 lines
        for indicator in markdown_indicators:
            if line.strip().startswith(indicator) or indicator in line:
                indicator_count += 1
                break
        if indicator_count >= threshold:
            break

    # Require at least some markdown formatting
    if indicator_count < threshold:
        raise ValueError(
            f"Content doesn't appear to be markdown (only {indicator_count} markdown indicators found)"
        )

    # Check for common documentation patterns
    doc_patterns = [
        "installation",
        "usage",
        "example",
        "api",
        "configuration",
        "claude",
        "code",
    ]
    content_lower = content.lower()
    pattern_found = any(pattern in content_lower for pattern in doc_patterns)

    if not pattern_found:
        logger.warning(
            f"Content for {filename} doesn't contain expected documentation patterns"
        )


def fetch_markdown_content(url: str, session: requests.Session) -> tuple[str, str]:
    """Fetch markdown content from a complete URL.

    Returns:
        Tuple of (filename, content).
    """
    filename = url_to_safe_filename(url)

    logger.info(f"Fetching: {url} -> {filename}")

    for attempt in range(MAX_RETRIES):
        try:
            response = safe_get(session, url, headers=HEADERS, timeout=30)

            # Handle specific HTTP errors
            if response.status_code == 429:  # Rate limited
                try:
                    wait_time = max(
                        0, min(int(response.headers.get("Retry-After", 60)), 300)
                    )
                except (ValueError, TypeError):
                    wait_time = 60
                logger.warning(f"Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue

            response.raise_for_status()

            # Guard against oversized responses
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    size = int(content_length)
                except (ValueError, TypeError):
                    logger.warning(
                        f"Malformed Content-Length header: {content_length!r}"
                    )
                else:
                    if size > MAX_RESPONSE_SIZE:
                        raise ValueError(f"Response too large: {content_length} bytes")

            # Get content and validate
            content = response.text[:MAX_RESPONSE_SIZE]
            validate_markdown_content(content, filename)

            logger.info(
                f"Successfully fetched and validated {filename} ({len(content)} bytes)"
            )
            return filename, content

        except requests.exceptions.RequestException as e:
            logger.warning(
                f"Attempt {attempt + 1}/{MAX_RETRIES} failed for {filename}: {e}"
            )
            if attempt < MAX_RETRIES - 1:
                # Exponential backoff with jitter
                delay = min(RETRY_DELAY * (2**attempt), MAX_RETRY_DELAY)
                # Add jitter to prevent thundering herd
                jittered_delay = delay * random.uniform(0.5, 1.0)  # noqa: S311
                logger.info(f"Retrying in {jittered_delay:.1f} seconds...")
                time.sleep(jittered_delay)
            else:
                raise FetchError(
                    f"Failed to fetch {filename} after {MAX_RETRIES} attempts: {e}"
                ) from e

        except ValueError as e:
            logger.error(f"Content validation failed for {filename}: {e}")
            raise

    raise FetchError(
        f"Failed to fetch {filename}: exhausted retries due to rate limiting"
    )


def content_has_changed(content: str, old_hash: str) -> bool:
    """Check if content has changed based on hash."""
    new_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return new_hash != old_hash


def fetch_changelog(session: requests.Session) -> tuple[str, str]:
    """Fetch Claude Code changelog from GitHub repository.

    Returns:
        Tuple of (filename, content).
    """
    changelog_url = (
        "https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md"
    )
    filename = "changelog.md"

    logger.info(f"Fetching Claude Code changelog: {changelog_url}")

    for attempt in range(MAX_RETRIES):
        try:
            response = safe_get(session, changelog_url, headers=HEADERS, timeout=30)

            if response.status_code == 429:  # Rate limited
                try:
                    wait_time = max(
                        0, min(int(response.headers.get("Retry-After", 60)), 300)
                    )
                except (ValueError, TypeError):
                    wait_time = 60
                logger.warning(f"Rate limited. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue

            response.raise_for_status()

            # Guard against oversized responses
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    size = int(content_length)
                except (ValueError, TypeError):
                    logger.warning(
                        f"Malformed Content-Length header: {content_length!r}"
                    )
                else:
                    if size > MAX_RESPONSE_SIZE:
                        raise ValueError(f"Response too large: {content_length} bytes")

            content = response.text[:MAX_RESPONSE_SIZE]

            # Add header to indicate this is from Claude Code repo, not docs site
            header = """# Claude Code Changelog

> **Source**: https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md
>
> This is the official Claude Code release changelog, automatically fetched from the Claude Code repository. For documentation, see other topics via `/docs`.

---

"""
            content = header + content

            # Basic validation
            if len(content.strip()) < 100:
                raise ValueError(f"Changelog content too short ({len(content)} bytes)")

            logger.info(f"Successfully fetched changelog ({len(content)} bytes)")
            return filename, content

        except requests.exceptions.RequestException as e:
            logger.warning(
                f"Attempt {attempt + 1}/{MAX_RETRIES} failed for changelog: {e}"
            )
            if attempt < MAX_RETRIES - 1:
                delay = min(RETRY_DELAY * (2**attempt), MAX_RETRY_DELAY)
                jittered_delay = delay * random.uniform(0.5, 1.0)  # noqa: S311
                logger.info(f"Retrying in {jittered_delay:.1f} seconds...")
                time.sleep(jittered_delay)
            else:
                raise FetchError(
                    f"Failed to fetch changelog after {MAX_RETRIES} attempts: {e}"
                ) from e

        except ValueError as e:
            logger.error(f"Changelog validation failed: {e}")
            raise

    raise FetchError(
        "Failed to fetch changelog: exhausted retries due to rate limiting"
    )


def save_markdown_file(docs_dir: Path, filename: str, content: str) -> str:
    """Save markdown content and return its hash."""
    file_path = (docs_dir / filename).resolve()

    # Ensure the resolved path stays within docs_dir
    if not file_path.is_relative_to(docs_dir.resolve()):
        raise ValueError(
            f"Path traversal detected: {filename} resolves outside {docs_dir}"
        )

    try:
        file_path.write_text(content, encoding="utf-8")
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        logger.info(f"Saved: {filename}")
        return content_hash
    except OSError as e:
        logger.error(f"Failed to save {filename}: {e}")
        raise


def process_fetched_content(
    docs_dir: Path,
    filename: str,
    content: str,
    manifest: dict,
    manifest_entry: dict,
) -> tuple[str, str]:
    """Check for changes, save if needed, return (content_hash, last_updated)."""
    old_entry = manifest.get("files", {}).get(filename, {})
    old_hash = old_entry.get("hash", "")

    if content_has_changed(content, old_hash):
        content_hash = save_markdown_file(docs_dir, filename, content)
        logger.info(f"Updated: {filename}")
        last_updated = datetime.now().isoformat()
    else:
        content_hash = old_hash
        logger.info(f"Unchanged: {filename}")
        last_updated = old_entry.get("last_updated", datetime.now().isoformat())

    manifest_entry.update({"hash": content_hash, "last_updated": last_updated})
    return content_hash, last_updated


def cleanup_old_files(docs_dir: Path, current_files: set[str], manifest: dict) -> None:
    """
    Remove only files that were previously fetched but no longer exist.
    Preserves manually added files.
    """
    previous_files = set(manifest.get("files", {}).keys())
    files_to_remove = previous_files - current_files
    resolved_docs_dir = docs_dir.resolve()

    for filename in files_to_remove:
        if filename == MANIFEST_FILE:  # Never delete the manifest
            continue

        file_path = (docs_dir / filename).resolve()
        # Ensure the resolved path stays within docs_dir
        if not file_path.is_relative_to(resolved_docs_dir):
            logger.warning(
                f"Skipping cleanup of {filename}: resolves outside {docs_dir}"
            )
            continue

        if file_path.exists():
            logger.info(f"Removing obsolete file: {filename}")
            file_path.unlink()


def main() -> None:
    """Main function — discovers pages from llms.txt and fetches documentation."""
    start_time = datetime.now()
    logger.info("Starting Claude Code documentation fetch")

    # Log configuration
    github_repo = os.environ.get("GITHUB_REPOSITORY", "doublefx/claude-code-docs")
    logger.info(f"GitHub repository: {github_repo}")

    # Create docs directory at repository root
    docs_dir = Path(__file__).parent.parent / "plugin" / "docs"
    docs_dir.mkdir(exist_ok=True)
    logger.info(f"Output directory: {docs_dir}")

    # Load manifest
    manifest = load_manifest(docs_dir)

    # Statistics
    successful = 0
    failed = 0
    failed_pages = []
    fetched_files: set[str] = set()
    new_manifest: dict = {"files": {}}

    # Create a session for connection pooling
    with requests.Session() as session:
        session.verify = True  # Explicit TLS certificate verification

        # Discover documentation pages from llms.txt
        discovered_pages = discover_pages_from_llms_txt(session)

        if not discovered_pages:
            logger.error("No documentation pages discovered!")
            sys.exit(1)

        # Fetch each discovered page
        for i, (title, page_url) in enumerate(discovered_pages, 1):
            logger.info(f"Processing {i}/{len(discovered_pages)}: {page_url}")

            try:
                filename, content = fetch_markdown_content(page_url, session)

                entry = {
                    "original_url": page_url,
                    "title": title,
                }
                process_fetched_content(docs_dir, filename, content, manifest, entry)
                new_manifest["files"][filename] = entry

                fetched_files.add(filename)
                successful += 1

                # Rate limiting
                if i < len(discovered_pages):
                    time.sleep(RATE_LIMIT_DELAY)

            except Exception as e:
                logger.error(f"Failed to process {page_url}: {e}")
                failed += 1
                failed_pages.append(page_url)

        # Fetch hierarchical docs map as a navigable reference
        logger.info("Fetching documentation map...")
        try:
            filename_map, content_map = fetch_markdown_content(DOCS_MAP_URL, session)
            # Rename to docs_map.md for clarity
            filename_map = "docs_map.md"
            entry = {
                "original_url": DOCS_MAP_URL,
                "title": "Documentation Map",
                "source": "docs-map",
            }
            process_fetched_content(
                docs_dir, filename_map, content_map, manifest, entry
            )
            new_manifest["files"][filename_map] = entry
            fetched_files.add(filename_map)
            successful += 1
        except Exception as e:
            logger.error(f"Failed to fetch docs map: {e}")
            failed += 1
            failed_pages.append("docs_map")

        # Fetch Claude Code changelog
        logger.info("Fetching Claude Code changelog...")
        try:
            filename, content = fetch_changelog(session)

            entry = {
                "original_url": "https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md",
                "original_raw_url": "https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md",
                "source": "claude-code-repository",
            }
            process_fetched_content(docs_dir, filename, content, manifest, entry)
            new_manifest["files"][filename] = entry

            fetched_files.add(filename)
            successful += 1

        except Exception as e:
            logger.error(f"Failed to fetch changelog: {e}")
            failed += 1
            failed_pages.append("changelog")

    # Clean up old files (only those we previously fetched)
    cleanup_old_files(docs_dir, fetched_files, manifest)

    # Add metadata to manifest
    end_time = datetime.now()
    new_manifest["fetch_metadata"] = {
        "last_fetch_completed": end_time.isoformat(),
        "fetch_duration_seconds": (end_time - start_time).total_seconds(),
        "total_pages_discovered": len(discovered_pages),
        "pages_fetched_successfully": successful,
        "pages_failed": failed,
        "failed_pages": failed_pages,
        "llms_txt_url": LLMS_TXT_URL,
        "total_files": len(fetched_files),
        "fetch_tool_version": "4.0",
    }

    # Save new manifest
    save_manifest(docs_dir, new_manifest)

    # Summary
    duration = end_time - start_time
    logger.info("\n" + "=" * 50)
    logger.info(f"Fetch completed in {duration}")
    logger.info(f"Discovered pages: {len(discovered_pages)}")
    logger.info(f"Successful: {successful}/{len(discovered_pages) + 2}")
    logger.info(f"Failed: {failed}")

    if failed_pages:
        logger.warning("\nFailed pages (will retry next run):")
        for page in failed_pages:
            logger.warning(f"  - {page}")
        # Don't exit with error - partial success is OK
        if successful == 0:
            logger.error("No pages were fetched successfully!")
            sys.exit(1)
    else:
        logger.info("\nAll pages fetched successfully!")


if __name__ == "__main__":
    main()
