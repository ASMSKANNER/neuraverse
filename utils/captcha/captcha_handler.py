import asyncio
import json
import base64
import urllib.parse
from urllib.parse import urlparse
from typing import Optional, Tuple

from loguru import logger

from utils.browser import Browser
from utils.db_api.models import Wallet
from data.settings import Settings


class CaptchaHandler:
    """Handler for solving hCaptcha via CapMonster API."""

    def __init__(self, wallet: Wallet):
        self.browser = Browser(wallet=wallet)

    async def parse_proxy(
        self,
    ) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str], Optional[str]]:
        """
        Returns:
            Tuple[ip, port, login, password, proxy_type]
        """
        proxy_raw = getattr(self.browser.wallet, "proxy", None)
        if not proxy_raw:
            return None, None, None, None, None

        parsed = urlparse(proxy_raw if "://" in proxy_raw else f"http://{proxy_raw}")
        ip = parsed.hostname
        port = parsed.port
        login = parsed.username
        password = parsed.password

        scheme = (parsed.scheme or "http").lower()
        proxy_type_map = {
            "http": "http",
            "https": "http",
            "socks5": "socks5",
            "socks4": "socks4",
        }
        proxy_type = proxy_type_map.get(scheme, "http")

        return ip, port, login, password, proxy_type

    def encode_html_to_base64(self, html_content: str) -> str:
        encoded = urllib.parse.quote(html_content)
        unescaped = urllib.parse.unquote(encoded)
        return base64.b64encode(unescaped.encode("latin1")).decode("ascii")

    async def _create_hcaptcha_task(
        self,
        websiteURL: str,
        siteKey: str,
        is_invisible: bool = True,
        rqdata: Optional[str] = None,
        task_type: str = "HCaptchaTurboTask",
    ) -> Optional[int]:
        """Create hCaptcha task in CapMonster. Returns task ID or None."""
        try:
            ip, port, login, password, proxy_type = await self.parse_proxy()

            # Determine final task type (with/without proxy)
            if ip and port:
                # If proxy exists, ensure we use non‑proxyless version
                if task_type.endswith("Proxyless"):
                    task_type = task_type.replace("Proxyless", "")
            else:
                # If no proxy, use proxyless version
                if not task_type.endswith("Proxyless"):
                    task_type = f"{task_type}Proxyless"

            task_data = {
                "type": task_type,
                "websiteURL": websiteURL,
                "websiteKey": siteKey,
                "isInvisible": is_invisible,
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
            }

            # Add rqdata if provided (sometimes required for invisible hCaptcha)
            if rqdata:
                task_data["rqdata"] = rqdata

            # Add proxy details if available
            if ip and port:
                task_data.update({
                    "proxyType": proxy_type,  # "http" or "socks5"
                    "proxyAddress": ip,
                    "proxyPort": port,
                })
                if login and password:
                    task_data.update({
                        "proxyLogin": login,
                        "proxyPassword": password,
                    })

            json_data = {
                "clientKey": Settings().capmonster_api_key,
                "task": task_data,
            }

            logger.debug(f"CapMonster task payload: {json_data}")

            resp = await self.browser.post(
                url="https://api.capmonster.cloud/createTask",
                json=json_data,
            )

            if resp.status_code != 200:
                logger.error(f"{self.browser.wallet} CapMonster HTTP error {resp.status_code}: {resp.text}")
                return None

            result = json.loads(resp.text)
            if result.get("errorId") != 0:
                logger.error(f"{self.browser.wallet} CapMonster error: {result.get('errorDescription', 'Unknown')}")
                return None

            task_id = result.get("taskId")
            logger.info(f"{self.browser.wallet} Created hCaptcha task (ID={task_id})")
            return task_id

        except Exception as e:
            logger.error(f"{self.browser.wallet} Failed to create hCaptcha task: {e}")
            return None

    async def _get_task_result(self, task_id: int) -> Optional[dict]:
        """Poll CapMonster for task result. Returns solution dict or None."""
        json_data = {
            "clientKey": Settings().capmonster_api_key,
            "taskId": task_id,
        }

        max_attempts = 60
        for _ in range(max_attempts):
            try:
                resp = await self.browser.post(
                    url="https://api.capmonster.cloud/getTaskResult",
                    json=json_data,
                )
                if resp.status_code != 200:
                    logger.error(f"{self.browser.wallet} Task result HTTP error {resp.status_code}")
                    await asyncio.sleep(2)
                    continue

                result = json.loads(resp.text)
                if result.get("status") == "ready":
                    logger.debug(f"Task {task_id} solution: {result}")
                    return result.get("solution")
                elif result.get("status") == "processing":
                    await asyncio.sleep(1)
                    continue
                else:
                    logger.error(f"{self.browser.wallet} Unknown task status: {result.get('status')}")
                    return None

            except Exception as e:
                logger.error(f"{self.browser.wallet} Error polling task {task_id}: {e}")
                await asyncio.sleep(2)

        logger.error(f"{self.browser.wallet} Timeout waiting for task {task_id}")
        return None

    async def hcaptcha_token(
        self,
        websiteURL: str,
        siteKey: str,
        is_invisible: bool = True,
        rqdata: Optional[str] = None,
        task_type: str = "HCaptchaTurboTask",
    ) -> Optional[str]:
        """
        Solve hCaptcha and return token.
        Args:
            websiteURL: Page URL where captcha is located.
            siteKey: hCaptcha site key.
            is_invisible: Whether captcha is invisible.
            rqdata: Optional rqdata parameter (if needed).
            task_type: CapMonster task type (default HCaptchaTurboTask).
        Returns:
            Captcha token string or None if failed.
        """
        if not Settings().capmonster_api_key:
            raise ValueError("CapMonster API key is missing in settings.yaml")

        max_retries = 10
        for attempt in range(1, max_retries + 1):
            try:
                task_id = await self._create_hcaptcha_task(
                    websiteURL=websiteURL,
                    siteKey=siteKey,
                    is_invisible=is_invisible,
                    rqdata=rqdata,
                    task_type=task_type,
                )
                if not task_id:
                    logger.warning(f"{self.browser.wallet} Failed to create task, attempt {attempt}/{max_retries}")
                    await asyncio.sleep(2)
                    continue

                solution = await self._get_task_result(task_id)
                if solution:
                    token = solution.get("gRecaptchaResponse") or solution.get("token")
                    if token:
                        logger.success(f"{self.browser.wallet} Successfully obtained hCaptcha token")
                        return token
                    else:
                        logger.warning(f"{self.browser.wallet} Solution missing token field: {solution}")

                logger.warning(f"{self.browser.wallet} No token received, attempt {attempt}/{max_retries}")

            except Exception as e:
                logger.error(f"{self.browser.wallet} Error during hCaptcha solving: {e}")

            await asyncio.sleep(3)

        logger.error(f"{self.browser.wallet} All retries exhausted, hCaptcha solving failed")
        return None
