import httpx
import time
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class CaptchaHandler:
    """
    Решение капчи через локальный сервер OhMyCaptcha
    Совместим с YesCaptcha API (createTask / getTaskResult)
    """
    
    def __init__(self, base_url: str = "http://localhost:8000", client_key: str = ""):
        """
        :param base_url: URL вашего сервера OhMyCaptcha (по умолчанию http://localhost:8000)
        :param client_key: CLIENT_KEY из .env файла OhMyCaptcha
        """
        self.base_url = base_url.rstrip('/')
        self.client_key = client_key
        self.session = httpx.Client(timeout=60.0)
    
    def _create_task(self, task_type: str, website_url: str, website_key: str, 
                     page_action: str = "", proxy: Optional[str] = None) -> Optional[str]:
        """
        Создает задачу на решение капчи
        
        :return: task_id или None при ошибке
        """
        task_data = {
            "type": task_type,
            "websiteURL": website_url,
            "websiteKey": website_key
        }
        
        if page_action:
            task_data["pageAction"] = page_action
        
        # Поддержка прокси (если нужно)
        if proxy:
            # Парсим прокси из строки формата http://user:pass@ip:port
            task_data["proxyType"] = "http"
            task_data["proxyAddress"] = proxy.split('@')[-1].split(':')[0]
            task_data["proxyPort"] = int(proxy.split(':')[-1].split('/')[0])
            if '@' in proxy:
                auth = proxy.split('://')[1].split('@')[0]
                task_data["proxyLogin"] = auth.split(':')[0]
                task_data["proxyPassword"] = auth.split(':')[1]
        
        payload = {
            "clientKey": self.client_key,
            "task": task_data
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/createTask",
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get("errorId") == 0 and data.get("taskId"):
                logger.debug(f"Task created: {data['taskId']}")
                return data["taskId"]
            else:
                logger.error(f"Error creating task: {data}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create captcha task: {e}")
            return None
    
    def _get_task_result(self, task_id: str, max_wait: int = 120, poll_interval: int = 5) -> Optional[str]:
        """
        Получает результат решения капчи
        
        :return: токен решения или None
        """
        payload = {
            "clientKey": self.client_key,
            "taskId": task_id
        }
        
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                response = self.session.post(
                    f"{self.base_url}/getTaskResult",
                    json=payload
                )
                response.raise_for_status()
                data = response.json()
                
                if data.get("status") == "ready":
                    # Для разных типов задач токен может быть в разных полях
                    solution = data.get("solution", {})
                    token = solution.get("gRecaptchaResponse") or solution.get("token")
                    if token:
                        logger.debug(f"Captcha solved: {token[:50]}...")
                        return token
                    else:
                        logger.error(f"No token in solution: {solution}")
                        return None
                        
                elif data.get("status") == "processing":
                    logger.debug(f"Task {task_id} still processing...")
                    time.sleep(poll_interval)
                    continue
                else:
                    logger.error(f"Unexpected task status: {data}")
                    return None
                    
            except Exception as e:
                logger.error(f"Failed to get task result: {e}")
                time.sleep(poll_interval)
                continue
        
        logger.error(f"Timeout waiting for captcha solution (task_id={task_id})")
        return None
    
    def solve_recaptcha_v2(self, website_url: str, website_key: str, 
                           proxy: Optional[str] = None) -> Optional[str]:
        """
        Решает reCAPTCHA v2 (NoCaptchaTaskProxyless)
        """
        task_id = self._create_task(
            task_type="NoCaptchaTaskProxyless",
            website_url=website_url,
            website_key=website_key,
            proxy=proxy
        )
        if not task_id:
            return None
        
        return self._get_task_result(task_id)
    
    def solve_recaptcha_v3(self, website_url: str, website_key: str, 
                           page_action: str = "homepage",
                           proxy: Optional[str] = None) -> Optional[str]:
        """
        Решает reCAPTCHA v3 (RecaptchaV3TaskProxyless)
        """
        task_id = self._create_task(
            task_type="RecaptchaV3TaskProxyless",
            website_url=website_url,
            website_key=website_key,
            page_action=page_action,
            proxy=proxy
        )
        if not task_id:
            return None
        
        return self._get_task_result(task_id)
    
    def solve_hcaptcha(self, website_url: str, website_key: str,
                       proxy: Optional[str] = None) -> Optional[str]:
        """
        Решает hCaptcha (HCaptchaTaskProxyless)
        """
        task_id = self._create_task(
            task_type="HCaptchaTaskProxyless",
            website_url=website_url,
            website_key=website_key,
            proxy=proxy
        )
        if not task_id:
            return None
        
        return self._get_task_result(task_id)
    
    def solve_turnstile(self, website_url: str, website_key: str,
                        proxy: Optional[str] = None) -> Optional[str]:
        """
        Решает Cloudflare Turnstile (TurnstileTaskProxyless)
        """
        task_id = self._create_task(
            task_type="TurnstileTaskProxyless",
            website_url=website_url,
            website_key=website_key,
            proxy=proxy
        )
        if not task_id:
            return None
        
        return self._get_task_result(task_id)
    
    def close(self):
        """Закрывает HTTP сессию"""
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


# ========== Совместимость со старым интерфейсом Capmonster ==========

class CapmonsterHandler(CaptchaHandler):
    """
    Класс-заглушка для обратной совместимости с существующим кодом
    """
    
    def __init__(self, api_key: str = "", base_url: str = "http://localhost:8000", client_key: str = ""):
        """
        :param api_key: игнорируется, оставлен для совместимости
        :param base_url: URL вашего OhMyCaptcha
        :param client_key: CLIENT_KEY из .env OhMyCaptcha
        """
        super().__init__(base_url=base_url, client_key=client_key)
    
    def solve_captcha(self, website_url: str, website_key: str) -> Optional[str]:
        """
        Основной метод, который используется в коде Neuraverse
        По умолчанию использует reCAPTCHA v2
        """
        return self.solve_recaptcha_v2(website_url, website_key)
