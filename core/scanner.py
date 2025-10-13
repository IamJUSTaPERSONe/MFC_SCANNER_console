# core/scanner.py
import re
import time
import logging
import urllib.parse
from typing import List, Dict, Any, Callable, Optional
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

    # def disable_slow_scanners(self):
    #     """Отключает медленные сканеры для быстрого режима"""
    #     try:
    #         # ID медленных и редко полезных сканеров
    #         slow_scanner_ids = [
    #             "40012",  # Buffer Overflow
    #             "40014",  # Parameter Tampering
    #             "40016",  # Cross-Domain Misconfiguration
    #             "40017",  # Server Side Include
    #             "40018",  # CRLF Injection
    #             "40026",  # HTTP Response Splitting
    #             "40027",  # Timestamp Disclosure
    #             "40028",  # Username Hash Disclosure
    #             "40032",  # XPath Injection
    #             "40033",  # XSLT Injection
    #         ]
    #
    #         disabled_count = 0
    #         for scanner_id in slow_scanner_ids:
    #             try:
    #                 self.zap.ascan.disable_scanners(scanner_id)
    #                 disabled_count += 1
    #             except Exception:
    #                 # Игнорируем если сканер не найден
    #                 continue
    #
    #         logger.info(f"✅ Отключено {disabled_count} медленных сканеров")
    #
    #     except Exception as e:
    #         logger.warning(f'Не удалось отключить сканеры {e}')

    def diagnose_scanners(self):
        """Показывает статус критически важных сканеров"""
        try:
            scanners = self.zap.ascan.scanners()

            # Критически важные сканеры
            critical_scanners = [
                "SQL Injection",
                "Cross Site Scripting",
                "XSS",
                "Path Traversal",
                "OS Command Injection",
                "Code Injection",
                "File Inclusion"
            ]

            enabled_critical = []
            disabled_critical = []

            for scanner in scanners:
                name = scanner.get('name', '')
                if any(crit in name for crit in critical_scanners):
                    if scanner.get('enabled') == 'true':
                        enabled_critical.append(name)
                    else:
                        disabled_critical.append(name)

            logger.info(f"🔴 КРИТИЧЕСКИЕ СКАНЕРЫ:")
            logger.info(f"✅ Включено: {len(enabled_critical)}")
            for scanner in enabled_critical:
                logger.info(f"      - {scanner}")

            logger.info(f"❌ Отключено: {len(disabled_critical)}")
            for scanner in disabled_critical[:5]:  # Первые 5
                logger.info(f" - {scanner}")

            return len(enabled_critical) > 0

        except Exception as e:
            logger.error(f"Ошибка диагностики сканеров: {e}")
            return False

    def _filter_alerts(self, alerts, scan_mode: str):
        """Агрессивная фильтрация уязвимостей в зависимости от режима"""
        filtered = []

        # РАСШИРЕННЫЙ СПИСОК ЛОЖНЫХ СРАБАТЫВАНИЙ
        false_positives = [
            "Server Leaks Version Information",
            "Server Leaks Information via",
            "X-Powered-By Header",
            "X-AspNet-Version Response Header",
            "X-Debug-Token Link",
            "Application Error Disclosure",
            "Content Security Policy (CSP) Header Not Set",
            "X-Content-Type-Options Header Missing",
            "X-Frame-Options Header Not Set",
            "Missing Anti-clickjacking Header",
            "Cookie No HttpOnly Flag",
            "Cookie Without Secure Flag",
            "Absence of Anti-CSRF Tokens",
            "Cross-Domain JavaScript Source File Inclusion",
            "Private IP Disclosure",
            "Timestamp Disclosure",
            "Username Hash Disclosure",
        ]

        for alert in alerts:
            risk = alert.get("risk", "Informational")
            name = alert.get("name", "Unknown")

            # Игнорируем
            if risk == "Informational":
                continue

            # Для быстрого режима супер агрессивная фильтрация
            if scan_mode == "fast":
                # Только High риски и реальные уязвимости
                if risk == "High":
                    pass
                elif risk == "Medium":
                    important_medium = [
                        "SQL Injection", "XSS", "Path Traversal",
                    "Command Injection", "File Upload"
                    ]
                    if not any(imp in name for imp in important_medium):
                        continue
                else:
                    continue

            # Для среднего режима
            elif scan_mode == "medium":
                # High + Medium, но фильтруем ложные срабатывания
                if risk not in ["High", "Medium"]:
                    continue

            # для полного - только фильтруем явные ложные срабатывания
            elif scan_mode == "deep":
                if any(fp in name for fp in false_positives):
                    continue


            # Если прошли все фильтры - добавляем
            filtered.append({
                "name": name,
                "risk": risk,
                "url": alert.get("url", ""),
                "description": alert.get("description", "")[:200],  # Обрезаем длинные описания
                "solution": alert.get("solution", "")
            })

        return filtered

    def enable_missing_critical_scanners(self):
        """Включает отключенные критические сканеры"""
        try:
            scanners = self.zap.ascan.scanners()

            must_enable = [
                "Cross Site Scripting",
                "XSS",
                "SQL Injection"  # базовый SQL injection
            ]

            enabled_count = 0
            for scanner in scanners:
                name = scanner.get('name', '')
                scanner_id = scanner.get('id', '')

                # Включаем если сканер критический И отключен
                if any(pattern in name for pattern in must_enable):
                    if scanner.get('enabled') != 'true':
                        try:
                            self.zap.ascan.enable_scanners(scanner_id)
                            enabled_count += 1
                            logger.info(f"✅ ВКЛЮЧЕН: {name}")
                        except Exception as e:
                            logger.warning(f"Не удалось включить {name}: {e}")

            if enabled_count > 0:
                logger.info(f"🎯 Включено недостающих сканеров: {enabled_count}")

        except Exception as e:
            logger.error(f"Ошибка включения сканеров: {e}")

    # Основное сканирование
    def scan(
        self,
        target_url: str,
        scan_mode: str = "fast",
        on_progress: Optional[Callable[[str, int], None]] = None
    ) -> List[Dict[str, Any]]:

        depth_configs = {
            'fast': {
                'max_duration': 3,  # 3 минут
                'max_children': 10,  # 10 дочерних узлов
                'max_depth': 2,
                'attack_strength': 'MEDIUM',
                'alert_threshold': 'MEDIUM',
                'timeout': 180,
                'disable_slow_scanners': True
            },
            'medium': {
                'max_duration': 10,  # 10 минут
                'max_children': 20,  # 20 дочерних узлов
                'max_depth': 3,
                'attack_strength': 'MEDIUM',
                'alert_threshold': 'MEDIUM',
                'timeout': 600,
                'disable_slow_scanners': False
            },
            'deep': {
                'max_duration': 25,  # 25 минут
                'max_children': 30,  # 30 дочерних узлов
                'max_depth': 4,
                'attack_strength': 'HIGH',
                'alert_threshold': 'LOW',
                'timeout': 1500,
                'disable_slow_scanners': False
            }
        }
        has_critical_scanners = self.diagnose_scanners()
        if not has_critical_scanners:
            logger.error("❌ КРИТИЧЕСКАЯ ОШИБКА: Нет включенных критических сканеров!")
        config = depth_configs.get(scan_mode, depth_configs['fast'])
        self.enable_missing_critical_scanners()

        try:
            # НАСТРОЙКИ SPIDER
            self.zap.spider.set_option_max_children(config["max_children"])
            self.zap.spider.set_option_max_depth(config["max_depth"])

            # НАСТРОЙКИ ACTIVE SCAN
            self.zap.ascan.set_option_max_scan_duration_in_mins(config["max_duration"])

            # Настройка через установку значений атрибутов
            self.zap.ascan.option_attack_strength = "HIGH"  # Всегда HIGH для теста!
            self.zap.ascan.option_alert_threshold = "LOW"  # Всегда LOW для теста!

            logger.info("✅ Применены агрессивные настройки: HIGH интенсивность, LOW порог")


           # Отключение медленных сканеров
           #  if config['disable_slow_scanners']:
           #      self.disable_slow_scanners()

            logger.info(f'Применен режим {scan_mode}: {config['max_duration']}, максимальная глубина {config['max_depth']}')


        except Exception as e:
            logger.warning(f"Не удалось применить часть настроек: {e}")

        if not target_url.startswith(('http://', 'https://')):
                raise ValueError("URL должен начинаться с http:// или https://")

        parsed = urllib.parse.urlparse(target_url)
        local_patterns = ['localhost', '127.0.0.1', '192.168.', 'fc00:']
        if any(pattern in parsed.netloc for pattern in local_patterns):
            raise ValueError('Сканирование локальных адресов запрещено')

        # Проверка, что это валидный доменчик
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', parsed.netloc):
            raise ValueError('Некорректный формат домена')

        # SPIDER SCAN
        logger.info(f"Запуск 🕷SPIDER🕷...Обход сайта -> {target_url}")
        if on_progress:
            on_progress("spider", 0)
        spider_result = self.zap.spider.scan(target_url)
        if not spider_result.isdigit():
            logger.error(f"❌ Ошибка запуска 🕷SPIDER🕷: {spider_result} ❌")
            return []
        spider_id = spider_result

        while True:
            try:
                spider_stat = int(self.zap.spider.status(spider_id))

                # вместо print
                if on_progress:
                    on_progress("spider", spider_stat)
                else:
                    print(f"\r🔍 Прогресс сканирования SPIDER -> {spider_stat}%", end="", flush=True)

                if spider_stat >= 100:
                    if not on_progress:
                        print()  # новая строка только в консоли
                    logger.info("✅ Сканирование SPIDER завершено")
                    break
                time.sleep(2)

            except Exception as e:
                if not on_progress:
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

        #  Отслеживает прогресс сканирования и подгоняет проценты под это
        start_time = time.time()

        scan_durations = {
            'fast': 180,  # 3 min
            'medium': 600,  # 10 min
            'deep': 1500   # 25 min
        }

        scan_duration = scan_durations.get(scan_mode, 600)

        while True:
            try:
                elapsed_time = time.time() - start_time
                zap_status = int(self.zap.ascan.status(ascan_id))

                time_progress = min((elapsed_time / scan_duration) * 100, 100)
                combined_progress = min(int((time_progress + zap_status) / 2), 100)

                # Но гарантируем, что прогресс не отстает от времени
                final_progress = max(combined_progress, int(time_progress))

                if on_progress:
                    on_progress("active_scan", final_progress)
                else:
                    print(f"\r🔍 Прогресс сканирования ACTIVE SCAN -> {final_progress}%", end="", flush=True)

                # Завершаем когда прошло достаточно времени И ZAP близок к завершению
                if elapsed_time >= scan_duration and zap_status >= 80:
                    if not on_progress:
                        print()
                    logger.info(f"✅ {scan_mode} сканирование завершено")
                    break

                # Или если прошло максимальное время
                if elapsed_time >= scan_duration * 1.2:  # +20% запаса
                    if not on_progress:
                        print()
                    logger.info(f"✅ Достигнут лимит времени для {scan_mode} режима")
                    break

                time.sleep(2)

            except Exception as e:
                if not on_progress:
                    print()
                logger.error(f"❌ Ошибка: {e} ❌")
                break


            # Безопасное получение результатов
        try:
            alerts = self.zap.core.alerts(baseurl=target_url)

            risk_distribution = {}
            for alert in alerts:
                risk = alert.get('risk', 'Informational')
                risk_distribution[risk] = risk_distribution.get(risk, 0) + 1

            logger.info(f"📊 Распределение уязвимостей по рискам: {risk_distribution}")

            from collections import Counter
            alert_names = [alert.get('name', 'Unknown') for alert in alerts]
            common_alerts = Counter(alert_names).most_common(10)
            logger.info(f"🔝 Топ-10 типов уязвимостей: {common_alerts}")

            filtered_alerts = self._filter_alerts(alerts, scan_mode)

            # Диагностика после фильтрации
            filtered_stats = {}
            for alert in filtered_alerts:
                risk = alert.get("risk", "Unknown")
                filtered_stats[risk] = filtered_stats.get(risk, 0) + 1

            logger.info(f"✅ После фильтрации: {len(filtered_alerts)} уязвимостей {filtered_stats}")

            return filtered_alerts


        except Exception as e:
            logger.error(f"❌ Ошибка при получении предупреждений: {e} ❌")
            return []