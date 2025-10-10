import sys
import logging
import flet as ft

# Настройка логирования
logging.basicConfig(level=logging.INFO)

def run_console_scan(target_url: str, scan_mode: str = 'fast'):
    """Запуск сканирования в консольном режиме"""
    from core.scanner import ZapScanner
    from core.report import generate_html_report

    scanner = ZapScanner()

    if not scanner.is_ready():
        print("❌ ZAP не запущен. Выполни: docker-compose up -d")
        sys.exit(1)

    print(f"🔍 Сканирую сайт: {target_url} в режиме '{scan_mode}'")
    vulnerabilities = scanner.scan(target_url, scan_mode=scan_mode)

    report_path = generate_html_report()
    print(f"✅ Найдено уязвимостей: {len(vulnerabilities)}")
    print(f"📄 Отчёт сохранён: {report_path}")

    for v in vulnerabilities[:3]:  # первые 3 уязвимости
        print(f"[{v['risk']}] {v['name']} → {v['url']}")

def show_help():
    """Показывает справку по использованию"""
    print("Использование:")
    print("  python main.py <URL>          → сканирование в консоли")
    print("  python main.py --gui          → запуск графического интерфейса")
    print("  python main.py --help         → эта справка")
    print("")
    print("Режимы сканирования:")
    print("  python main.py <URL> fast     → быстрое сканирование (3-5 мин")
    print("  python main.py <URL> medium   → стандартное сканирование (10-15 мин")
    print("  python main.py <URL> deep     → полное сканирование (25-30 мин")

def main():
    if len(sys.argv) == 1:
        show_help()
        sys.exit(1)

    if sys.argv[1] in ("--help", "-h"):
        show_help()
        return

    if sys.argv[1] == "--gui":
        # Запуск графического интерфейса
        try:
            from interface.flet_ui import main as flet_main
            print("🚀 Запуск графического интерфейса...")
            ft.app(target=flet_main)
        except ImportError as e:
            print(f"❌ Ошибка импорта Flet UI: {e}")
            print("Убедитесь, что файл interface/flet_ui.py существует и структура папок верна.")
            sys.exit(1)
        except Exception as e:
            print(f"💥 Ошибка при запуске GUI: {e}")
            sys.exit(1)
    else:
        # Консольный режим
        target = sys.argv[1]

        #  Определяет режим сканирования
        scan_mode = 'fast'
        if len(sys.argv) >= 3:
            mode = sys.argv[2].lower()
            if mode in ['fast', 'medium', 'deep']:
                scan_mode = mode
            else:
                print(f'Неизвестный режим {mode}, использую "fast"')
        run_console_scan(target, scan_mode)

if __name__ == "__main__":
    main()