"""
base.py — Abstract base collector for living-threat-intel
All collectors inherit from this. Handles retry, rate limiting, logging.
"""

import abc
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


@dataclass
class CollectorResult:
    source: str
    collected_at: str
    cves: list[dict] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    error: Optional[str] = None
    raw_count: int = 0

    @property
    def success(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "collected_at": self.collected_at,
            "cves": self.cves,
            "iocs": self.iocs,
            "error": self.error,
            "raw_count": self.raw_count,
        }


class BaseCollector(abc.ABC):
    """
    Abstract base for all living-threat-intel collectors.

    Subclasses must implement:
      - SOURCE_NAME: str class attribute
      - collect() -> CollectorResult

    Rate limiting is opt-in: set rate_limit_delay (seconds between requests).
    Retry logic uses exponential backoff by default.
    """

    SOURCE_NAME: str = "unknown"

    # Override in subclasses as needed
    rate_limit_delay: float = 0.0          # seconds between requests
    max_retries: int = 3
    backoff_factor: float = 2.0            # wait = backoff_factor * (2 ** retry_num)
    timeout: int = 30                       # per-request timeout (seconds)

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._session = self._build_session()
        self._last_request_time: float = 0.0

    def _build_session(self) -> requests.Session:
        """Build a requests.Session with connection-level retry for transient failures."""
        session = requests.Session()

        # urllib3-level retry handles connection errors and 5xx responses
        retry = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        session.headers.update({"User-Agent": "living-threat-intel/1.0 (github.com/ruwgxo/living-threat-intel)"})
        return session

    def _throttle(self) -> None:
        """Enforce rate limit between requests."""
        if self.rate_limit_delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_time
        wait = self.rate_limit_delay - elapsed
        if wait > 0:
            logger.debug(f"[{self.SOURCE_NAME}] Rate limit: sleeping {wait:.2f}s")
            time.sleep(wait)
        self._last_request_time = time.monotonic()

    def get(self, url: str, params: Optional[dict] = None, headers: Optional[dict] = None) -> Optional[requests.Response]:
        """
        Throttled GET with application-level retry on top of urllib3 retry.
        Returns None on unrecoverable failure.
        """
        self._throttle()
        attempt = 0
        while attempt <= self.max_retries:
            try:
                resp = self._session.get(url, params=params, headers=headers, timeout=self.timeout)
                if resp.status_code == 429:
                    # Respect Retry-After if present
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    logger.warning(f"[{self.SOURCE_NAME}] 429 rate limited — sleeping {retry_after}s")
                    time.sleep(retry_after)
                    attempt += 1
                    continue
                resp.raise_for_status()
                return resp
            except requests.exceptions.ConnectionError as e:
                wait = self.backoff_factor ** attempt
                logger.warning(f"[{self.SOURCE_NAME}] Connection error (attempt {attempt}): {e}. Retrying in {wait}s")
                time.sleep(wait)
                attempt += 1
            except requests.exceptions.Timeout:
                wait = self.backoff_factor ** attempt
                logger.warning(f"[{self.SOURCE_NAME}] Timeout (attempt {attempt}). Retrying in {wait}s")
                time.sleep(wait)
                attempt += 1
            except requests.exceptions.HTTPError as e:
                logger.error(f"[{self.SOURCE_NAME}] HTTP error: {e}")
                return None

        logger.error(f"[{self.SOURCE_NAME}] All {self.max_retries} retries exhausted for {url}")
        return None

    def post(self, url: str, json: Optional[dict] = None, headers: Optional[dict] = None) -> Optional[requests.Response]:
        """Throttled POST — same retry semantics as get()."""
        self._throttle()
        try:
            resp = self._session.post(url, json=json, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            return resp
        except requests.exceptions.RequestException as e:
            logger.error(f"[{self.SOURCE_NAME}] POST failed: {e}")
            return None

    def now_utc(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def make_result(self, **kwargs: Any) -> CollectorResult:
        return CollectorResult(
            source=self.SOURCE_NAME,
            collected_at=self.now_utc(),
            **kwargs,
        )

    def error_result(self, message: str) -> CollectorResult:
        logger.error(f"[{self.SOURCE_NAME}] {message}")
        return CollectorResult(
            source=self.SOURCE_NAME,
            collected_at=self.now_utc(),
            error=message,
        )

    @abc.abstractmethod
    def collect(self) -> CollectorResult:
        """Fetch threat data and return a CollectorResult. Must be implemented by subclasses."""
        ...
