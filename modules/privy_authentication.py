import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from urllib.parse import urlparse

from eth_account.messages import encode_defunct
from loguru import logger

from data.constants import DEFAULT_HEADERS
from libs.eth_async.client import Client
from utils.browser import Browser
from utils.captcha.captcha_handler import CaptchaHandler
from utils.db_api.models import Wallet
from utils.db_api.wallet_api import update_wallet_info


class PrivyAuth:
    __module__ = "Privy authentication"

    BASE_URL = "https://privy.neuraprotocol.io/api/v1"

    _refresh_semaphore = asyncio.Semaphore(2)
    _siwe_semaphore = asyncio.Semaphore(1)

    def __init__(self, client: Client, wallet: Wallet):
        self.client = client
        self.wallet = wallet

        # Keep auth requests in the wallet proxy-context
        self.session = Browser(wallet=self.wallet)

        self.authentication = False
        self.token_id = self.resolve_privy_ca_id()

        self.headers = {
            **DEFAULT_HEADERS,
            "privy-app-id": "cmbpempz2011ll10l7iucga14",
            "privy-ca-id": self.token_id,
            "privy-client": "react-auth:3.12.0",  # Обновлено с 2.25.0 на 3.12.0
        }

    def __repr__(self):
        return f"{self.__module__} | [{self.wallet.address}]"

    @property
    def cookies(self) -> dict:
        return {
            k: v
            for k, v in (self.wallet.cookies or {}).items()
            if k in {
                "privy-token",
                "privy-id-token",
                "privy-session",
                "privy-refresh-token",
                "privy-access-token",
            }
        }

    def _get_browser_params(self) -> Dict[str, Any]:
        """
        Получает параметры браузера для передачи в OhMyCaptcha.
        Использует реальные cookies из кошелька и стандартные настройки.
        """
        params = {
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
            "viewport": {"width": 1920, "height": 1080},
            "locale": "en-US",
            "platform": "Windows",
        }
        
        # Добавляем cookies из кошелька (все куки)
        if self.wallet.cookies:
            params["cookies"] = self.wallet.cookies
            logger.debug(f"Using {len(self.wallet.cookies)} cookies from wallet")
        
        # Добавляем прокси для диагностики
        if self.wallet.proxy:
            params["proxy"] = self.wallet.proxy
        
        logger.debug(f"Browser params prepared: userAgent={params['userAgent'][:50]}..., viewport={params['viewport']}, cookies_count={len(params.get('cookies', {}))}")
        return params

    def _persist_auth_state(self, session_token: str, identity_token: str, cookies: dict) -> None:
        update_wallet_info(address=self.wallet.address, name_column="session_token", data=session_token)
        update_wallet_info(address=self.wallet.address, name_column="identity_token", data=identity_token)
        update_wallet_info(address=self.wallet.address, name_column="cookies", data=cookies)

        self.wallet.session_token = session_token
        self.wallet.identity_token = identity_token
        self.wallet.cookies = cookies

    def _merge_cookie_dicts(self, *cookie_dicts: dict) -> dict:
        merged: dict = {}
        for item in cookie_dicts:
            if not item:
                continue
            merged.update({k: v for k, v in item.items() if v})
        return merged

    async def privy_authorize(self) -> bool:
        if self.cookies:
            try:
                logger.info(f"{self.wallet} | Trying refresh via cookie")
                refresh_status = await self.refresh_session_via_cookie()

                if refresh_status is True:
                    self.authentication = True
                    logger.success(
                        f"{self.wallet} | Refresh via cookie: OK (session_token & identity_token & cookies updated)"
                    )
                    return True

                if refresh_status is None:
                    if self.wallet.session_token and self.wallet.identity_token and self.cookies:
                        self.authentication = True
                        logger.warning(f"{self.wallet} | Refresh rate-limited (429), continue with cached session")
                        return True

                    logger.warning(f"{self.wallet} | Refresh rate-limited and no cached session available")
                else:
                    logger.warning(f"{self.wallet} | Refresh via cookie failed")

            except Exception as e:
                logger.warning(f"{self.wallet} | Failed to refresh session via cookies — {e}")

        # If cookies not working, fallback to full SIWE with captcha
        logger.info(f"{self.wallet} | Getting new session_token via SIWE...")
        if await self.authenticate_via_siwe():
            self.authentication = True
            logger.success(f"{self.wallet} | SIWE: OK (session_token & identity_token & cookies saved)")
            return True
        else:
            logger.error(f"{self.wallet} | SIWE failed: session_token, identity_token or cookies missing")
            return False

    async def refresh_session_via_cookie(self) -> bool | None:
        async with PrivyAuth._refresh_semaphore:
            cookies = {
                k: v
                for k, v in (self.wallet.cookies or {}).items()
                if k in {
                    "privy-token",
                    "privy-id-token",
                    "privy-session",
                    "privy-refresh-token",
                    "privy-access-token",
                }
            }

            payload = {"refresh_token": "deprecated"}
            headers = self.headers.copy()

            if self.wallet.identity_token:
                headers["authorization"] = f"Bearer {self.wallet.identity_token}"

            try:
                response = await self.session.post(
                    url=f"{self.BASE_URL}/sessions",
                    cookies=cookies,
                    headers=headers,
                    json=payload,
                )

                if response.status_code != 200:
                    if response.status_code == 429:
                        logger.warning(f"{self.wallet} | Refresh request rate-limited (429). Body: {response.text}")
                        return None

                    logger.error(f"{self.wallet} | Non-200 response ({response.status_code}). Body: {response.text}")
                    return False

            except Exception as e:
                logger.error(f"{self.wallet} | Refresh request failed — {e}")
                return False

            try:
                data = response.json()
                session_token = data.get("token")
                identity_token = data.get("identity_token")

                response_cookies = self.extract_privy_tokens(response.headers.get("set-cookie"))
                merged_cookies = self._merge_cookie_dicts(cookies, response_cookies)

                if not (session_token and identity_token and merged_cookies):
                    logger.error(
                        f"{self.wallet} | Refresh failed "
                        f"(session_token={bool(session_token)}, identity_token={bool(identity_token)}, "
                        f"cookies={bool(merged_cookies)})"
                    )
                    return False

                self._persist_auth_state(
                    session_token=session_token,
                    identity_token=identity_token,
                    cookies=merged_cookies,
                )
                return True

            except Exception as e:
                logger.error(f"{self.wallet} | Failed to parse refresh response — {e}")
                return False

    async def authenticate_via_siwe(self) -> bool:
        async with PrivyAuth._siwe_semaphore:
            try:
                nonce = await self.get_nonce()
                logger.debug(f"{self.wallet} | Nonce obtained: {nonce[:8] + '...' if nonce else 'None'}")
            except Exception as e:
                logger.error(f"{self.wallet} | Failed to obtain nonce — {e}")
                return False

            message = self.siwe_message(nonce=nonce)
            signature = self.client.account.sign_message(signable_message=encode_defunct(text=message))

            payload = {
                "message": message,
                "signature": signature.signature.hex(),
                "chainId": "eip155:267",
                "walletClientType": "metamask",
                "connectorType": "injected",
                "mode": "login-or-sign-up",
            }

            try:
                response = await self.session.post(
                    url=f"{self.BASE_URL}/siwe/authenticate",
                    headers=self.headers,
                    json=payload,
                )
                if response.status_code != 200:
                    logger.error(f"{self.wallet} | Non-200 response ({response.status_code}). Body: {response.text}")
                    return False

                data = response.json()
                session_token = data.get("token")
                identity_token = data.get("identity_token")
                is_new_user = data.get("is_new_user", False)

                raw_set_cookie = response.headers.get("set-cookie")
                cookie_header = self.extract_privy_tokens(raw_set_cookie)

                if not (session_token and identity_token and cookie_header):
                    logger.error(
                        f"{self.wallet} | SIWE: FAILED (session_token={bool(session_token)},"
                        f"identity_token={bool(identity_token)}, cookie={bool(cookie_header)})"
                    )
                    return False

                self._persist_auth_state(
                    session_token=session_token,
                    identity_token=identity_token,
                    cookies=cookie_header,
                )

                # Send analytics events
                if not await self.send_analytics_events(is_new_user=is_new_user):
                    logger.error(f"{self.wallet} | Analytics events failed")
                    return False

                return True

            except Exception as e:
                logger.error(f"{self.wallet} | Failed to complete SIWE authentication — {e}")
                return False

    async def get_nonce(self) -> str:
        try:
            captcha_handler = CaptchaHandler(wallet=self.wallet)
            
            # Получаем параметры браузера
            browser_params = self._get_browser_params()
            logger.debug(f"{self.wallet} | Browser params: {list(browser_params.keys())}")

            # Решаем hCaptcha через OhMyCaptcha с параметрами браузера
            captcha_token = await captcha_handler.hcaptcha_token(
                websiteURL="https://neuraverse.neuraprotocol.io/",
                siteKey="b9fc5a50-2e5c-457a-9582-80ce342c2534",
                is_invisible=True,
                browser_params=browser_params,
            )

            if not captcha_token:
                raise ValueError("Captcha token missing")

            logger.info(f"{self.wallet} | Captcha token obtained, length: {len(captcha_token)}")

        except Exception as e:
            logger.error(f"{self.wallet} | Failed to obtain captcha token — {e}")
            raise

        payload = {
            "address": self.wallet.address,
            "token": captcha_token,
        }

        try:
            response = await self.session.post(
                url=f"{self.BASE_URL}/siwe/init",
                headers=self.headers,
                json=payload,
            )
            if response.status_code != 200:
                logger.error(f"{self.wallet} | Non-200 response ({response.status_code}). Body: {response.text}")
                raise RuntimeError("Failed to get nonce")

            nonce = response.json().get("nonce")
            if not nonce:
                logger.error(f"{self.wallet} | Nonce missing in response body")
                raise ValueError("Nonce missing in response")

            return nonce

        except Exception as e:
            logger.error(f"{self.wallet} | get_nonce(): request/parse error — {e}")
            raise

    async def send_analytics_events(self, is_new_user: bool) -> bool:
        try:
            cookies = {
                k: v
                for k, v in (self.wallet.cookies or {}).items()
                if k in {
                    "privy-token",
                    "privy-id-token",
                    "privy-session",
                    "privy-refresh-token",
                    "privy-access-token",
                }
            }

            headers = {
                **self.headers,
                "authorization": f"Bearer {self.wallet.identity_token}",
            }

            utc_time_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            payload = {
                "event_name": "sdk_authenticate_siwe",
                "client_id": self.token_id,
                "payload": {
                    "connectorType": "injected",
                    "walletClientType": "metamask",
                    "clientTimestamp": utc_time_now,
                },
            }

            response = await self.session.post(
                url=f"{self.BASE_URL}/analytics_events",
                cookies=cookies,
                headers=headers,
                json=payload,
            )
            if response.status_code != 200:
                logger.error(f"{self.wallet} | Non-200 response ({response.status_code}). Body: {response.text}")
                return False

            payload = {
                "event_name": "sdk_authenticate",
                "client_id": self.token_id,
                "payload": {
                    "method": "siwe",
                    "isNewUser": is_new_user,
                    "clientTimestamp": utc_time_now,
                },
            }

            response = await self.session.post(
                url=f"{self.BASE_URL}/analytics_events",
                cookies=cookies,
                headers=headers,
                json=payload,
            )
            if response.status_code != 200:
                logger.error(f"{self.wallet} | Non-200 response ({response.status_code}). Body: {response.text}")
                return False

            return True

        except Exception as e:
            logger.error(f"{self.wallet} | Analytics event processing failed — {e}")
            return False

    def siwe_message(self, nonce: str) -> str:
        issued_at = datetime.utcnow().isoformat() + "Z"

        return (
            "neuraverse.neuraprotocol.io wants you to sign in with your Ethereum account:\n"
            f"{self.wallet.address}\n\n"
            "By signing, you are proving you own this wallet and logging in. "
            "This does not initiate a transaction or cost any fees.\n\n"
            "URI: https://neuraverse.neuraprotocol.io\n"
            "Version: 1\n"
            "Chain ID: 267\n"
            f"Nonce: {nonce}\n"
            f"Issued At: {issued_at}\n"
            "Resources:\n"
            "- https://privy.io"
        )

    def resolve_privy_ca_id(self) -> str:
        wallet_addr = (self.wallet.address or "").lower()
        proxy_raw = self.wallet.proxy or ""
        proxy_norm = self.normalize_proxy(proxy_raw)

        seed = f"{wallet_addr}|{proxy_norm}" if proxy_norm else wallet_addr
        return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))

    def normalize_proxy(self, proxy: str) -> str:
        if not proxy:
            return ""

        try:
            p = urlparse(proxy if "://" in proxy else f"http://{proxy}")
            host = p.hostname or ""
            port = p.port

            if not host or not port:
                return ""

            return f"{host}:{port}"

        except Exception:
            return ""

    def extract_privy_tokens(self, set_cookie: str | None) -> Dict[str, str]:
        wanted = {
            "privy-token",
            "privy-id-token",
            "privy-refresh-token",
            "privy-access-token",
            "privy-session",
        }
        result: Dict[str, str] = {}

        if not set_cookie:
            return result

        for match in re.finditer(r"(?P<name>[^=;,\s]+)=(?P<value>[^;\r\n,]+)", set_cookie):
            name = match.group("name").strip()
            value = match.group("value").strip()

            if name in wanted:
                result[name] = value

        return result
