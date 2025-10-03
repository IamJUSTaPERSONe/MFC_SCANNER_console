# main.py
import sys
import logging
from core.scanner import ZapScanner
from core.report import generate_html_report

logging.basicConfig(level=logging.INFO)

def main():
    if len(sys.argv) != 2:
        print("Использование: python main.py <URL>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = ZapScanner()

    if not scanner.is_ready():
        print("❌ ZAP не запущен. Выполни: docker-compose up -d ❌")
        sys.exit(1)

    # print(f"🔍 Сканирую ваш сайт: {target}...")
    vulnerabilities = scanner.scan(target)

    report_path = generate_html_report()
    print(f"✅ Найдено уязвимостей: {len(vulnerabilities)}")
    print(f"📄 Отчёт создан в: {report_path}")

    for v in vulnerabilities[:3]:  # первые 3
        print(f"[{v['risk']}] {v['name']} → {v['url']}")

if __name__ == "__main__":
    main()
