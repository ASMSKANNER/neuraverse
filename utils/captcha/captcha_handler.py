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
from libs.baseAsyncSession import DEFAULT_USER_AGENT


class CaptchaHandler:
    """Handler for Cloudflare Turnstile protection"""

    def __init__(self, wallet: Wallet):
        self.browser = Browser(wallet=wallet)

    async def parse_proxy(self) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str], Optional[str]]:
        """
        Returns:
            Tuple[ip, port, login, password, proxy_type]
        """
        if not self.browser.wallet.proxy:
            return None, None, None, None, None

        parsed = urlparse(self.browser.wallet.proxy)
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
        base64_encoded = base64.b64encode(unescaped.encode("latin1")).decode("ascii")
        return base64_encoded

    async def get_recaptcha_task(
        self,
        websiteURL: str,
        captcha_id: str,
        challenge: str,
    ) -> Optional[int]:
        try:
            ip, port, login, password, proxy_type = await self.parse_proxy()

            json_data = {
                "clientKey": Settings().capmonster_api_key,
                "task": {
                    "type": "GeeTestTask",
                    "websiteURL": websiteURL,
                    "gt": captcha_id,
                    "challenge": challenge,
                    "version": 4,
                    "userAgent": DEFAULT_USER_AGENT,
                },
            }

            if ip and port:
                json_data["task"].update(
                    {
                        "proxyType": proxy_type or "http",
                        "proxyAddress": ip,
                        "proxyPort": port,
                    }
                )

            if login and password:
                json_data["task"].update(
                    {
                        "proxyLogin": login,
                        "proxyPassword": password,
                    }
                )

            resp = await self.browser.post(
                url="https://api.capmonster.cloud/createTask",
                json=json_data,
            )

            if resp.status_code == 200:
                result = json.loads(resp.text)
                if result.get("errorId") == 0:
                    logger.info(f"{self.browser.wallet} created task in CapMonster: {result['taskId']}")
                    return result["taskId"]

                logger.error(
                    f"{self.browser.wallet} CapMonster error: "
                    f"{result.get('errorDescription', 'Unknown error')}"
                )
                return None

            logger.error(f"{self.browser.wallet} CapMonster request error: {resp.status_code}")
            return None

        except Exception as e:
            logger.error(f"{self.browser.wallet} error creating task in CapMonster: {str(e)}")
            return None

    async def get_recaptcha_token(self, task_id: int):
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

                if resp.status_code == 200:
                    result = json.loads(resp.text)

                    if result["status"] == "ready":
                        logger.debug(result)
                        if "solution" in result:
                            return result["solution"]

                        logger.error(f"{self.browser.wallet} solution does not contain expected payload")
                        return None

                    elif result["status"] == "processing":
                        await asyncio.sleep(1)
                        continue

                    else:
                        logger.error(f"{self.browser.wallet} unknown task status: {result['status']}")
                        return None

                logger.error(f"{self.browser.wallet} error getting task result: {resp.status_code}")
                await asyncio.sleep(2)
                continue

            except Exception as e:
                logger.error(f"{self.browser.wallet} error getting task result: {str(e)}")
                return None

        logger.error(f"{self.browser.wallet} exceeded wait time for CapMonster solution")
        return None

    async def recaptcha_handle(self, websiteURL: str, captcha_id: str, challenge: str):
        max_retry = 10
        captcha_token = None

        if not Settings().capmonster_api_key:
            raise Exception("Insert CapMonster Api Key to files/settings.yaml")

        for i in range(max_retry):
            try:
                task = await self.get_recaptcha_task(
                    websiteURL=websiteURL,
                    captcha_id=captcha_id,
                    challenge=challenge,
                )
                logger.debug(f"{self.browser.wallet} get task from CapMonster {task}")

                if not task:
                    logger.error(
                        f"{self.browser.wallet} failed to create task in CapMonster, "
                        f"attempt {i + 1}/{max_retry}"
                    )
                    await asyncio.sleep(2)
                    continue

                result = await self.get_recaptcha_token(task_id=task)

                if result:
                    captcha_token = result
                    logger.success(f"{self.browser.wallet} successfully obtained captcha token")
                    break

                logger.warning(
                    f"{self.browser.wallet} failed to get token, attempt {i + 1}/{max_retry}"
                )
                await asyncio.sleep(3)

            except Exception as e:
                logger.error(f"{self.browser.wallet} error handling captcha: {str(e)}")
                await asyncio.sleep(3)

        return captcha_token

    async def cloudflare_token(self, websiteURL: str, websiteKey: str):
        max_retry = 1
        captcha_token = None

        if not Settings().capmonster_api_key:
            raise Exception("Insert CapMonster Api Key to files/settings.yaml")

        for i in range(max_retry):
            try:
                task = await self.get_recaptcha_task_cloudflare(
                    websiteURL=websiteURL,
                    websiterKey=websiteKey,
                )

                if not task:
                    logger.error(
                        f"{self.browser.wallet} failed to create task in CapMonster, "
                        f"attempt {i + 1}/{max_retry}"
                    )
                    await asyncio.sleep(2)
                    continue

                result = await self.get_recaptcha_token(task_id=task)

                if result:
                    captcha_token = result
                    logger.success(f"{self.browser.wallet} successfully obtained captcha token")
                    break

                logger.warning(
                    f"{self.browser.wallet} failed to get token, attempt {i + 1}/{max_retry}"
                )
                await asyncio.sleep(3)

            except Exception as e:
                logger.error(f"{self.browser.wallet} error handling captcha: {str(e)}")
                await asyncio.sleep(3)

        return captcha_token

    async def get_recaptcha_task_cloudflare(self, websiteURL: str, websiterKey: str):
        try:
            ip, port, login, password, proxy_type = await self.parse_proxy()

            json_data = {
                "clientKey": Settings().capmonster_api_key,
                "task": {
                    "type": "TurnstileTask",
                    "websiteURL": websiteURL,
                    "websiteKey": websiterKey,
                    "userAgent": DEFAULT_USER_AGENT,
                },
            }

            if ip and port:
                json_data["task"].update(
                    {
                        "proxyType": proxy_type or "http",
                        "proxyAddress": ip,
                        "proxyPort": port,
                    }
                )

            if login and password:
                json_data["task"].update(
                    {
                        "proxyLogin": login,
                        "proxyPassword": password,
                    }
                )

            logger.debug(
                f"{self.browser.wallet} Turnstile task config: "
                f"ua={DEFAULT_USER_AGENT}, proxy={bool(ip and port)}, proxy_type={proxy_type}"
            )

            resp = await self.browser.post(
                url="https://api.capmonster.cloud/createTask",
                json=json_data,
            )

            if resp.status_code == 200:
                result = json.loads(resp.text)
                if result.get("errorId") == 0:
                    logger.info(f"{self.browser.wallet} created task in CapMonster: {result['taskId']}")
                    return result["taskId"]

                logger.error(
                    f"{self.browser.wallet} CapMonster error: "
                    f"{result.get('errorDescription', 'Unknown error')}"
                )
                return None

            logger.error(f"{self.browser.wallet} CapMonster request error: {resp.status_code}")
            return None

        except Exception as e:
            logger.error(f"{self.browser.wallet} error creating task in CapMonster: {str(e)}")
            return None
