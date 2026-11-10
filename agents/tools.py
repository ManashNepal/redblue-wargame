import time
from pathlib import Path

import httpx
from strands import tool

TARGET_DIR = Path(__file__).resolve().parent.parent / "target_app"
LOG_PATH = TARGET_DIR / "access.log"

MAX_BODY_CHARS = 4000
MAX_LOG_LINES = 500
REQUEST_TIMEOUT_SECONDS = 10


def _resolve_target_file(filename: str) -> Path | None:
    """Return the file's path if it is a .py file directly inside target_app/, else None."""
    path = (TARGET_DIR / filename).resolve()
    if path.parent != TARGET_DIR or path.suffix != ".py" or not path.is_file():
        return None
    return path


def _available_files() -> list[str]:
    return sorted(p.name for p in TARGET_DIR.glob("*.py"))


@tool
def send_http_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> dict:
    """Send a single HTTP request to the target web application.

    Args:
        method: HTTP method, e.g. GET or POST.
        url: Full URL including scheme, host, port, path and query string.
        headers: Optional request headers, e.g. {"Authorization": "Bearer abc"}.
        body: Optional raw request body. Set a Content-Type header to match it.

    Returns:
        The status code, response headers, response body (truncated if long) and
        elapsed time in milliseconds, or an error message if the request failed.
    """
    start = time.perf_counter()
    try:
        response = httpx.request(
            method.upper(),
            url,
            headers=headers,
            content=body,
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    elapsed_ms = round((time.perf_counter() - start) * 1000, 1)

    text = response.text
    truncated = len(text) > MAX_BODY_CHARS
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": text[:MAX_BODY_CHARS],
        "body_truncated": truncated,
        "elapsed_ms": elapsed_ms,
    }


@tool
def read_access_log(last_n_lines: int = 50) -> str:
    """Read the most recent lines of the target application's access log.

    Each line has the format: timestamp client METHOD path?query status elapsed_ms

    Args:
        last_n_lines: How many of the most recent lines to return (max 500).

    Returns:
        The requested log lines, oldest first.
    """
    if not LOG_PATH.exists():
        return "The access log is empty: no requests have been made yet."
    n = max(1, min(last_n_lines, MAX_LOG_LINES))
    lines = LOG_PATH.read_text(encoding="utf-8").splitlines()
    return "\n".join(lines[-n:])


@tool
def read_target_file(filename: str) -> str:
    """Read a Python source file of the target application.

    Args:
        filename: A file name inside the target app, e.g. "app.py".

    Returns:
        The full file contents, or an error listing the files you may read.
    """
    path = _resolve_target_file(filename)
    if path is None:
        return f"Error: '{filename}' is not readable. Available files: {_available_files()}"
    return path.read_text(encoding="utf-8")


@tool
def edit_target_file(filename: str, old_text: str, new_text: str) -> str:
    """Patch a Python source file of the target application by replacing text.

    old_text must match the file exactly (including indentation) and appear
    exactly once. The app reloads automatically after an edit, which takes a
    moment; wait briefly before re-testing.

    Args:
        filename: A file name inside the target app, e.g. "app.py".
        old_text: The exact existing code to replace.
        new_text: The code to put in its place.

    Returns:
        A success message, or an error explaining why the edit was not applied.
    """
    path = _resolve_target_file(filename)
    if path is None:
        return f"Error: '{filename}' is not editable. Available files: {_available_files()}"

    source = path.read_text(encoding="utf-8")
    count = source.count(old_text)
    if count == 0:
        return "Error: old_text was not found in the file. Read the file and copy the text exactly."
    if count > 1:
        return f"Error: old_text appears {count} times. Include more surrounding lines so it is unique."

    path.write_text(source.replace(old_text, new_text, 1), encoding="utf-8")
    return (
        f"Edited {filename}: replaced {len(old_text)} chars with {len(new_text)} chars."
    )
