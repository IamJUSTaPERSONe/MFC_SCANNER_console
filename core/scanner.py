# core/scanner.py
import time
import logging
from typing import List, Dict, Any
from zapv2 import ZAPv2

logger = logging.getLogger(__name__)

class ZapScanner:
    def __init__(self, api_url: str = "http://localhost:8080", api_key: str = None):
        self.zap = ZAPv2(apikey=api_key, proxies={'http': api_url, 'https': api_url})

    # Проверка запуска сканера
    def is_ready(self) -> bool:
        try:
            version = self.zap.core.version
            logger.info(f"✅ OWASP ZAP запущен. ВЕРСИЯ: {version}")
            return True
        except Exception as e:
            logger.error(f"❌ ZAP недоступен: {e} ❌")
            return False

    # Валидация ввода
    def scan(self, target_url: str, timeout: int = 600) -> List[Dict[str, Any]]:
        if not target_url.startswith(('http://', 'https://')):
            raise ValueError("URL должен начинаться с http:// или https://")

        # SPIDER SCAN
        logger.info(f"Запуск 🕷SPIDER🕷...Обход сайта -> {target_url}")
        spider_result = self.zap.spider.scan(target_url)
        if not spider_result.isdigit():
            logger.error(f"❌ Ошибка запуска 🕷SPIDER🕷: {spider_result} ❌")
            return []
        spider_id = spider_result
        # Отслеживание прогресса сканирования SPIDER
        print("", end="", flush=True)

        while True:
            try:
                spider_stat = int(self.zap.spider.status(spider_id))

                # Вывод прогресса в одну строку
                print(f"\r🔍 Прогресс сканирования ACTIVE SCAN -> {spider_stat}%", end="", flush=True)

                if spider_stat >= 100:
                    print()  # Переход на новую строку после завершения
                    logger.info("✅ Сканирование SPIDER завершено")
                    print()
                    break
                time.sleep(2)

            except Exception as e:
                print()
                logger.error(f"❌ Ошибка при получение статуса SPIDER: {e} ❌")
                break

        # ACTIVE SCAN
        logger.info("Запуск ACTIVE SCAN...Проверка уязвимостей...")
        ascan_result = self.zap.ascan.scan(target_url, recurse=True)
        if not ascan_result.isdigit():
            logger.error(f"❌ Ошибка запуска ACTIVE SCAN: {ascan_result} ❌")
            return []
        ascan_id = ascan_result
        # Отслеживание статуса сканирования
        waited = 0
        print("", end="", flush=True)

        while True:
            try:
                status_str = self.zap.ascan.status(ascan_id)
                status_percent = int(status_str)

                # Вывод прогресса в одну строку
                print(f"\r🔍 Прогресс сканирования ACTIVE SCAN -> {status_percent}%", end="", flush=True)

                if status_percent >= 100:
                    print()  # Переход на новую строку после завершения
                    logger.info("✅ Сканирование ACTIVE SCAN завершено")
                    break
                time.sleep(5)
                waited += 5

                if waited > timeout:
                    print()
                    logger.warning(f"Достигнут таймаут сканирования ({timeout} сек)")
                    break

            except Exception as e:
                print()
                logger.error(f"❌ Ошибка при получение статуса ACTIVE SCAN: {e} ❌")
                break

        alerts = self.zap.core.alerts(baseurl=target_url)
        return [
            {
                "name": a.get("name"),
                "risk": a.get("risk"),
                "url": a.get("url"),
                "description": a.get("description"),
                "solution": a.get("solution")
            }
            for a in alerts
        ]