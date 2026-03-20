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
    """Handler for captcha solving via CapMonster"""

    def __init__(self, wallet: Wallet):
        self.browser = Browser(wallet=wallet)

    async def parse_proxy(self) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
        """
        Parse proxy string into components

        Returns:
            Tuple[ip, port, login, password]
        """
        if not self.browser.wallet.proxy:
            return None, None, None, None

        parsed = urlparse(self.browser.wallet.proxy)

        ip = parsed.hostname
        port = parsed.port
        login = parsed.username
        password = parsed.password

        return ip, port, login, password

    def encode_html_to_base64(self, html_content: str) -> str:
        """
        Encode HTML to base64 (kept for compatibility, not used in hCaptcha)
        """
        encoded = urllib.parse.quote(html_content)
        unescaped = urllib.parse.unquote(encoded)
        base64_encoded = base64.b64encode(unescaped.encode('latin1')).decode('ascii')
        return base64_encoded

    async def get_hcaptcha_task(self, websiteURL: str, siteKey: str) -> Optional[int]:
        """
        Create task for solving hCaptcha in CapMonster

        Args:
            websiteURL: URL of the page with hCaptcha
            siteKey: hCaptcha sitekey

        Returns:
            Task ID or None in case of error
        """
        try:
            ip, port, login, password = await self.parse_proxy()

            json_data = {
                "clientKey": Settings().capmonster_api_key,
                "task": {
                    "type": "HCaptchaTaskProxyless",  # default without proxy
                    "websiteURL": websiteURL,
                    "websiteKey": siteKey,
                }
            }

            # Use proxy if available
            if ip and port:
                json_data["task"]["type"] = "HCaptchaTask"
                json_data["task"].update({
                    "proxyType": "http",
                    "proxyAddress": ip,
                    "proxyPort": port
                })
                if login and password:
                    json_data["task"].update({
                        "proxyLogin": login,
                        "proxyPassword": password
                    })

            resp = await self.browser.post(
                url='https://api.capmonster.cloud/createTask',
                json=json_data,
            )

            if resp.status_code == 200:
                result = json.loads(resp.text)
                if result.get('errorId') == 0:
                    logger.info(f"{self.browser.wallet} created hCaptcha task in CapMonster: {result['taskId']}")
                    return result['taskId']
                else:
                    logger.error(f"{self.browser.wallet} CapMonster error: {result.get('errorDescription', 'Unknown error')}")
                    return None
            else:
                logger.error(f"{self.browser.wallet} CapMonster request error: {resp.status_code}")
                return None

        except Exception as e:
            logger.error(f"{self.browser.wallet} error creating hCaptcha task: {str(e)}")
            return None

    async def get_recaptcha_token(self, task_id: int) -> Optional[dict]:
        """
        Get task result from CapMonster

        Args:
            task_id: Task ID

        Returns:
            Solution dict (contains token) or None
        """
        json_data = {
            "clientKey": Settings().capmonster_api_key,
            "taskId": task_id
        }

        max_attempts = 60

        for _ in range(max_attempts):
            try:
                resp = await self.browser.post(
                    url='https://api.capmonster.cloud/getTaskResult',
                    json=json_data,
                )

                if resp.status_code == 200:
                    result = json.loads(resp.text)
                    if result['status'] == 'ready':
                        logger.debug(result)
                        if 'solution' in result:
                            return result['solution']
                        else:
                            logger.error(f"{self.browser.wallet} solution does not contain token")
                            return None
                    elif result['status'] == 'processing':
                        await asyncio.sleep(1)
                        continue
                    else:
                        logger.error(f"{self.browser.wallet} unknown task status: {result['status']}")
                        return None
                else:
                    logger.error(f"{self.browser.wallet} error getting task result: {resp.status_code}")
                    await asyncio.sleep(2)
                    continue

            except Exception as e:
                logger.error(f"{self.browser.wallet} error getting task result: {str(e)}")
                return None

        logger.error(f"{self.browser.wallet} exceeded wait time for CapMonster solution")
        return None

    async def hcaptcha_token(self, websiteURL: str, siteKey: str) -> Optional[str]:
        """
        Solve hCaptcha and return token

        Args:
            websiteURL: URL of the page with hCaptcha
            siteKey: hCaptcha sitekey

        Returns:
            Captcha token or None
        """
        max_retry = 10
        captcha_token = None

        if not Settings().capmonster_api_key:
            raise Exception("Insert CapMonster Api Key to files/settings.yaml")

        for i in range(max_retry):
            try:
                task_id = await self.get_hcaptcha_task(websiteURL=websiteURL, siteKey=siteKey)
                if not task_id:
                    logger.error(f"{self.browser.wallet} failed to create hCaptcha task, attempt {i+1}/{max_retry}")
                    await asyncio.sleep(2)
                    continue

                result = await self.get_recaptcha_token(task_id=task_id)
                if result:
                    # For hCaptcha, the token is usually under 'gRecaptchaResponse'
                    captcha_token = result.get('gRecaptchaResponse') or result.get('token')
                    if captcha_token:
                        logger.success(f"{self.browser.wallet} successfully obtained hCaptcha token")
                        break
                    else:
                        logger.warning(f"{self.browser.wallet} solution missing token field, attempt {i+1}/{max_retry}")
                else:
                    logger.warning(f"{self.browser.wallet} failed to get token, attempt {i+1}/{max_retry}")

                await asyncio.sleep(3)

            except Exception as e:
                logger.error(f"{self.browser.wallet} error handling hCaptcha: {str(e)}")
                await asyncio.sleep(3)

        return captcha_token
