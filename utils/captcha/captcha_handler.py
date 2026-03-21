import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from loguru import logger

from data.settings import Settings
from utils.browser import Browser
from utils.db_api.models import Wallet


class CaptchaErrorKind(str, Enum):
    CONFIG = "config"
    NETWORK = "network"
    TIMEOUT = "timeout"
    PROVIDER = "provider"
    RESPONSE = "response"
    UNSUPPORTED = "unsupported"


@dataclass
class CaptchaError(Exception):
    kind: CaptchaErrorKind
    message: str
    details: Optional[str] = None

    def __str__(self) -> str:
        if self.details:
            return f"[{self.kind}] {self.message}: {self.details}"
        return f"[{self.kind}] {self.message}"


@dataclass
class ProxyConfig:
    scheme: str
    host: str
    port: int
    login: Optional[str] = None
    password: Optional[str] = None

    @property
    def url(self) -> str:
        auth = ""
        if self.login and self.password:
            auth = f"{self.login}:{self.password}@"
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    @property
    def redacted_url(self) -> str:
        auth = ""
        if self.login and self.password:
            auth = "***:***@"
        return f"{self.scheme}://{auth}{self.host}:{self.port}"


class CaptchaHandler:
    """
    Решение hCaptcha (тип nn) через Astrum Solver.
    """

    CREATE_TASK_TIMEOUT = 20
    POLL_TIMEOUT = 20
    POLL_INTERVAL_SECONDS = 2
    MAX_POLL_ATTEMPTS = 30

    def __init__(self, wallet: Wallet):
        self.wallet = wallet
        self.browser = Browser(wallet=wallet)
        self.settings = Settings()

    @property
    def user_agent(self) -> str:
        return getattr(self.settings, "default_user_agent", None) or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/136.0.0.0 Safari/537.36"
        )

    def parse_proxy(self) -> Optional[ProxyConfig]:
        proxy_raw = getattr(self.wallet, "proxy", None)
        if not proxy_raw:
            return None

        parsed = urlparse(proxy_raw if "://" in proxy_raw else f"http://{proxy_raw}")
        scheme = (parsed.scheme or "http").lower()

        allowed_schemes = {"http", "https", "socks5", "socks4"}
        if scheme not in allowed_schemes:
            raise CaptchaError(
                kind=CaptchaErrorKind.CONFIG,
                message="Unsupported proxy scheme",
                details=scheme,
            )

        if not parsed.hostname or not parsed.port:
            raise CaptchaError(
                kind=CaptchaErrorKind.CONFIG,
                message="Proxy is missing host or port",
                details=proxy_raw,
            )

        normalized_scheme = "http" if scheme == "https" else scheme

        return ProxyConfig(
            scheme=normalized_scheme,
            host=parsed.hostname,
            port=parsed.port,
            login=parsed.username,
            password=parsed.password,
        )

    def _redact_value(self, key: str, value: Any) -> Any:
        lowered = key.lower()
        if lowered in {"clientkey", "apikey", "api_key", "token", "authorization"}:
            return "***"
        if lowered == "proxyurl" and isinstance(value, str):
            try:
                parsed = urlparse(value)
                if parsed.username and parsed.password:
                    redacted_netloc = f"***:***@{parsed.hostname}:{parsed.port}"
                else:
                    redacted_netloc = parsed.netloc
                redacted = parsed._replace(netloc=redacted_netloc)
                return urlunparse(redacted)
            except Exception:
                return "***"
        return value

    def _redact_payload(self, payload: Any) -> Any:
        if isinstance(payload, dict):
            return {k: self._redact_payload(self._redact_value(k, v)) for k, v in payload.items()}
        if isinstance(payload, list):
            return [self._redact_payload(v) for v in payload]
        return payload

    def _log_debug_payload(self, title: str, payload: dict[str, Any]) -> None:
        logger.debug(f"{self.wallet} | {title}: {self._redact_payload(payload)}")

    async def _post_json(
        self,
        *,
        url: str,
        json_payload: dict[str, Any],
        timeout_seconds: int,
        operation_name: str,
    ) -> dict[str, Any]:
        self._log_debug_payload(operation_name, json_payload)

        try:
            response = await asyncio.wait_for(
                self.browser.post(url=url, json=json_payload),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError as e:
            raise CaptchaError(
                kind=CaptchaErrorKind.TIMEOUT,
                message=f"{operation_name} timed out",
            ) from e
        except Exception as e:
            raise CaptchaError(
                kind=CaptchaErrorKind.NETWORK,
                message=f"{operation_name} request failed",
                details=str(e),
            ) from e

        if response.status_code != 200:
            raise CaptchaError(
                kind=CaptchaErrorKind.NETWORK,
                message=f"{operation_name} returned HTTP {response.status_code}",
                details=(response.text[:500] if getattr(response, "text", None) else None),
            )

        try:
            data = response.json()
        except Exception as e:
            text_preview = ""
            try:
                text_preview = response.text[:500]
            except Exception:
                pass
            raise CaptchaError(
                kind=CaptchaErrorKind.RESPONSE,
                message=f"{operation_name} returned non-JSON response",
                details=text_preview,
            ) from e

        if not isinstance(data, dict):
            raise CaptchaError(
                kind=CaptchaErrorKind.RESPONSE,
                message=f"{operation_name} returned invalid JSON type",
                details=type(data).__name__,
            )
        return data

    def _validate_api_key_present(self) -> None:
        api_key = getattr(self.settings, "astrum_api_key", None)
        if not api_key:
            raise CaptchaError(
                kind=CaptchaErrorKind.CONFIG,
                message="astrum_api_key is missing in settings",
            )

    def _build_hcaptcha_task_payload(
        self,
        website_url: str,
        site_key: str,
        rqdata: Optional[str] = None,
        is_invisible: bool = True,
    ) -> dict[str, Any]:
        self._validate_api_key_present()

        task_data: dict[str, Any] = {
            "type": "nn",
            "websiteURL": website_url,
            "siteKey": site_key,
            "isInvisible": is_invisible,
            "userAgent": self.user_agent,
        }

        if rqdata:
            task_data["rqdata"] = rqdata

        proxy = self.parse_proxy()
        if proxy:
            task_data["proxyURL"] = proxy.url

        return {
            "clientKey": self.settings.astrum_api_key,
            "task": task_data,
        }

    async def _create_hcaptcha_task(
        self,
        website_url: str,
        site_key: str,
        rqdata: Optional[str] = None,
        is_invisible: bool = True,
    ) -> str:
        payload = self._build_hcaptcha_task_payload(
            website_url=website_url,
            site_key=site_key,
            rqdata=rqdata,
            is_invisible=is_invisible,
        )

        data = await self._post_json(
            url="https://solver.astrum.foundation/api/createTask",
            json_payload=payload,
            timeout_seconds=self.CREATE_TASK_TIMEOUT,
            operation_name="createTask",
        )

        if data.get("errorId") != 0:
            raise CaptchaError(
                kind=CaptchaErrorKind.PROVIDER,
                message="Astrum error creating task",
                details=data.get("errorDescription", "Unknown error"),
            )

        task_id = data.get("taskId")
        if not task_id:
            raise CaptchaError(
                kind=CaptchaErrorKind.RESPONSE,
                message="Astrum response missing taskId",
            )

        logger.info(f"{self.wallet} | Created Astrum nn task: {task_id}")
        return task_id

    async def _get_task_result(self, task_id: str) -> dict[str, Any]:
        payload = {
            "clientKey": self.settings.astrum_api_key,
            "task": {
                "taskId": task_id,
                "type": "nn",
            },
        }

        for attempt in range(self.MAX_POLL_ATTEMPTS):
            data = await self._post_json(
                url="https://solver.astrum.foundation/api/getTaskResult",
                json_payload=payload,
                timeout_seconds=self.POLL_TIMEOUT,
                operation_name=f"getTaskResult (attempt {attempt+1})",
            )

            status = data.get("status")
            if status == "closed":
                solution = data.get("solution", {})
                logger.debug(f"{self.wallet} | Full solution from Astrum: {solution}")
                token = solution.get("token") or solution.get("gRecaptchaResponse")
                if not token:
                    raise CaptchaError(
                        kind=CaptchaErrorKind.RESPONSE,
                        message="Astrum returned solution without token",
                        details=str(solution),
                    )
                return solution
            elif status in ("processing", "in_progress", "opened"):
                await asyncio.sleep(self.POLL_INTERVAL_SECONDS)
                continue
            else:
                raise CaptchaError(
                    kind=CaptchaErrorKind.PROVIDER,
                    message=f"Astrum returned unknown status: {status}",
                    details=data.get("errorDescription"),
                )

        raise CaptchaError(
            kind=CaptchaErrorKind.TIMEOUT,
            message=f"Task {task_id} not solved after {self.MAX_POLL_ATTEMPTS} attempts",
        )

    async def hcaptcha_token(
        self,
        websiteURL: str,
        siteKey: str,
        is_invisible: bool = True,
        rqdata: Optional[str] = None,
    ) -> str:
        """
        Решает hCaptcha через Astrum Solver (тип nn) и возвращает токен.
        """
        self._validate_api_key_present()
        try:
            _ = self._build_hcaptcha_task_payload(
                website_url=websiteURL,
                site_key=siteKey,
                rqdata=rqdata,
                is_invisible=is_invisible,
            )
        except CaptchaError:
            raise
        except Exception as e:
            raise CaptchaError(
                kind=CaptchaErrorKind.CONFIG,
                message="Failed to build hCaptcha request",
                details=str(e),
            ) from e

        max_retries = 10
        for attempt in range(1, max_retries + 1):
            try:
                task_id = await self._create_hcaptcha_task(
                    website_url=websiteURL,
                    site_key=siteKey,
                    rqdata=rqdata,
                    is_invisible=is_invisible,
                )
                solution = await self._get_task_result(task_id)
                token = solution.get("token") or solution.get("gRecaptchaResponse")
                if token:
                    logger.success(f"{self.wallet} | hCaptcha solved successfully")
                    logger.debug(f"{self.wallet} | Token: {token[:50]}...")  # показываем начало токена
                    return token
                else:
                    logger.warning(f"{self.wallet} | Solution missing token: {solution}")
            except CaptchaError as e:
                logger.warning(f"{self.wallet} | Attempt {attempt}/{max_retries} failed: {e}")
            except Exception as e:
                logger.warning(f"{self.wallet} | Attempt {attempt}/{max_retries} unexpected error: {e}")

            await asyncio.sleep(3)

        raise CaptchaError(
            kind=CaptchaErrorKind.PROVIDER,
            message=f"All {max_retries} attempts to solve hCaptcha failed",
        )
