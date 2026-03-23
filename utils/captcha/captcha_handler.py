import httpx
import time
import logging
from typing import Optional
from urllib.parse import urlparse
from loguru import logger

import sys
sys.path.insert(0, '..')
from data.settings import settings


class CaptchaHandler:
    """
    Обработчик капчи через локальный сервер OhMyCaptcha с поддержкой прокси и невидимой капчи
    """
    
    def __init__(self, wallet=None, api_key: str = None):
        """
        :param wallet: объект кошелька (для передачи прокси)
        :param api_key: не используется, оставлен для совместимости
        """
        self.wallet = wallet
        
        # Настройки OhMyCaptcha
        self.ohmycaptcha_url = getattr(settings, 'ohmycaptcha_url', 'http://localhost:8000')
        self.ohmycaptcha_client_key = getattr(settings, 'ohmycaptcha_client_key', '')
        
        self.session = httpx.Client(timeout=60.0)
        
        if not self.ohmycaptcha_client_key:
            logger.warning("OhMyCaptcha client key not configured! Captcha solving will fail.")
        else:
            logger.debug(f"CaptchaHandler initialized with OhMyCaptcha at {self.ohmycaptcha_url}")
    
    def _parse_proxy(self, proxy_str: str) -> dict | None:
        """Парсит прокси из строки формата http://user:pass@ip:port"""
        if not proxy_str:
            return None
        try:
            parsed = urlparse(proxy_str if "://" in proxy_str else f"http://{proxy_str}")
            host = parsed.hostname
            port = parsed.port
            if not host or not port:
                return None
            result = {
                "proxyType": "http",
                "proxyAddress": host,
                "proxyPort": port,
            }
            if parsed.username and parsed.password:
                result["proxyLogin"] = parsed.username
                result["proxyPassword"] = parsed.password
            return result
        except Exception as e:
            logger.error(f"Failed to parse proxy: {e}")
            return None
    
    def _create_task(self, task_type: str, website_url: str, website_key: str, 
                     page_action: str = "", is_invisible: bool = True) -> Optional[str]:
        """
        Создаёт задачу в OhMyCaptcha.
        Поддерживает прокси (если у кошелька есть) и параметр isInvisible.
        """
        if not self.ohmycaptcha_client_key:
            logger.error("OhMyCaptcha client key missing")
            return None
            
        task_data = {
            "type": task_type,
            "websiteURL": website_url,
            "websiteKey": website_key
        }
        
        if page_action:
            task_data["pageAction"] = page_action
        
        # Для hCaptcha добавляем параметр isInvisible (по умолчанию True)
        if task_type in ("HCaptchaTaskProxyless", "HCaptchaTask"):
            task_data["isInvisible"] = is_invisible
            logger.debug(f"Set isInvisible={is_invisible} for hCaptcha task")
        
        # Добавляем прокси, если у кошелька есть
        if self.wallet and hasattr(self.wallet, 'proxy') and self.wallet.proxy:
            proxy_config = self._parse_proxy(self.wallet.proxy)
            if proxy_config:
                task_data.update(proxy_config)
                logger.info(f"Using proxy for captcha: {proxy_config['proxyAddress']}:{proxy_config['proxyPort']}")
            else:
                logger.warning(f"Could not parse proxy: {self.wallet.proxy}")
        else:
            logger.debug("No proxy provided for captcha task")
        
        payload = {
            "clientKey": self.ohmycaptcha_client_key,
            "task": task_data
        }
        
        try:
            response = self.session.post(
                f"{self.ohmycaptcha_url}/createTask",
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get("errorId") == 0 and data.get("taskId"):
                logger.debug(f"OhMyCaptcha task created: {data['taskId']}")
                return data["taskId"]
            else:
                logger.error(f"OhMyCaptcha error: {data}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create OhMyCaptcha task: {e}")
            return None
    
    def _get_task_result(self, task_id: str, max_wait: int = 300, poll_interval: int = 5) -> Optional[str]:
        """
        Получает результат из OhMyCaptcha
        """
        if not self.ohmycaptcha_client_key:
            logger.error("OhMyCaptcha client key missing")
            return None
            
        payload = {
            "clientKey": self.ohmycaptcha_client_key,
            "taskId": task_id
        }
        
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                response = self.session.post(
                    f"{self.ohmycaptcha_url}/getTaskResult",
                    json=payload
                )
                response.raise_for_status()
                data = response.json()
                
                if data.get("status") == "ready":
                    solution = data.get("solution", {})
                    token = solution.get("gRecaptchaResponse") or solution.get("token")
                    if token:
                        logger.debug(f"OhMyCaptcha solved: {token[:50]}...")
                        return token
                    else:
                        logger.error(f"No token in solution: {solution}")
                        return None
                        
                elif data.get("status") == "processing":
                    logger.debug(f"OhMyCaptcha task {task_id} processing...")
                    time.sleep(poll_interval)
                    continue
                else:
                    logger.error(f"Unexpected OhMyCaptcha status: {data}")
                    return None
                    
            except Exception as e:
                logger.error(f"Failed to get OhMyCaptcha result: {e}")
                time.sleep(poll_interval)
                continue
        
        logger.error(f"OhMyCaptcha timeout for task {task_id}")
        return None
    
    # ========== Основные методы для решения капчи ==========
    
    async def hcaptcha_token(self, websiteURL: str, siteKey: str, is_invisible: bool = True) -> Optional[str]:
        """
        Решение hCaptcha через OhMyCaptcha
        Асинхронный метод для совместимости со старым интерфейсом Neuraverse
        """
        logger.debug(f"Solving hCaptcha with OhMyCaptcha: {websiteURL}")
        
        task_id = self._create_task(
            task_type="HCaptchaTaskProxyless",
            website_url=websiteURL,
            website_key=siteKey,
            is_invisible=is_invisible
        )
        if not task_id:
            return None
        
        return self._get_task_result(task_id)
    
    async def recaptcha_v2_token(self, websiteURL: str, siteKey: str) -> Optional[str]:
        """
        Решение reCAPTCHA v2 через OhMyCaptcha
        """
        logger.debug(f"Solving reCAPTCHA v2 with OhMyCaptcha: {websiteURL}")
        
        task_id = self._create_task(
            task_type="NoCaptchaTaskProxyless",
            website_url=websiteURL,
            website_key=siteKey
        )
        if not task_id:
            return None
        
        return self._get_task_result(task_id)
    
    async def recaptcha_v3_token(self, websiteURL: str, siteKey: str, action: str = "homepage") -> Optional[str]:
        """
        Решение reCAPTCHA v3 через OhMyCaptcha
        """
        logger.debug(f"Solving reCAPTCHA v3 with OhMyCaptcha: {websiteURL}")
        
        task_id = self._create_task(
            task_type="RecaptchaV3TaskProxyless",
            website_url=websiteURL,
            website_key=siteKey,
            page_action=action
        )
        if not task_id:
            return None
        
        return self._get_task_result(task_id)
    
    async def turnstile_token(self, websiteURL: str, siteKey: str) -> Optional[str]:
        """
        Решение Cloudflare Turnstile через OhMyCaptcha
        """
        logger.debug(f"Solving Turnstile with OhMyCaptcha: {websiteURL}")
        
        task_id = self._create_task(
            task_type="TurnstileTaskProxyless",
            website_url=websiteURL,
            website_key=siteKey
        )
        if not task_id:
            return None
        
        return self._get_task_result(task_id)
    
    def close(self):
        """Закрывает HTTP сессию"""
        if hasattr(self, 'session') and self.session:
            self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
