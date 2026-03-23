import httpx
import time
import logging
from typing import Optional, Dict, Any
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
                     page_action: str = "", is_invisible: bool = True,
                     browser_params: Dict[str, Any] = None) -> Optional[str]:
        """
        Создаёт задачу в OhMyCaptcha.
        Поддерживает прокси (если у кошелька есть) и параметр isInvisible.
        
        :param browser_params: параметры браузера (userAgent, viewport, locale, cookies)
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
        
        # Добавляем параметры браузера, если переданы
        if browser_params:
            if "userAgent" in browser_params:
                task_data["userAgent"] = browser_params["userAgent"]
                logger.debug(f"Set userAgent: {browser_params['userAgent'][:50]}...")
            
            if "viewport" in browser_params:
                task_data["viewport"] = browser_params["viewport"]
                logger.debug(f"Set viewport: {browser_params['viewport']}")
            
            if "locale" in browser_params:
                task_data["locale"] = browser_params["locale"]
                logger.debug(f"Set locale: {browser_params['locale']}")
            
            if "platform" in browser_params:
                task_data["platform"] = browser_params["platform"]
                logger.debug(f"Set platform: {browser_params['platform']}")
            
            if "cookies" in browser_params and browser_params["cookies"]:
                # Преобразуем cookies в формат, понятный OhMyCaptcha
                cookie_list = []
                for name, value in browser_params["cookies"].items():
                    cookie_list.append({"name": name
