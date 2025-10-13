import time
import urllib.parse
import flet as ft
from core.scanner import ZapScanner
from core.report import generate_html_report
import webbrowser
import requests
import os


# Цветовая схема
COLORS = {
    "bg_primary": "#0A0E17",
    "bg_card": "#1A1F2E",
    "primary": "#7B68EE",
    "secondary": "#8b42ff",
    "text_primary": "#FFFFFF",
    "text_secondary": "#B0B0B0",
    "success": "#00FF88",
    "warning": "#FFAA00",
    "error": "#FF4444"
}

help_text = """
Это приложение автоматически проверяет сайты на наличие уязвимостей с помощью инструмента OWASP ZAP.

Возможности:
- Анализ структуры сайта с помощью инструмента SPIDER
- Поиск уязвимостей (XSS, SQLi и др)
- Генерация отчета 

ПРЕДУПРЕЖДЕНИЯ:
- Перед сканированием убедитесь, что ZAP запущен: docker-compose up -d
- НЕ СКАНИРУЙТЕ САЙТЫ БЕЗ РАЗРЕШЕНИЯ
- Для тестового запуска используйте: https://testhtml5.vulnweb.com

О режимах работы:
- Быстрое сканирование (до 5 минут) -> поверхностно сканирует до пяти дочерних узлов. Только критические уязвимости
- Стандартное сканирование (до 10 минут) -> оптимальное сканирование до десяти дочерних узлов. 
- Полное сканирование (до 20 минут) -> сканирует до двадцати пяти дочерних узлов. Максимальная проверка

Проект для безопасности информационной жизни, 2025
"""


class VulnerabilityScannerUI:
    def __init__(self, page: ft.Page):
        self.page = page
        self.setup_page()
        self.create_ui()
        self.scan_history = []

    def add_to_history(self, url: str, vulnerabilities: list):
        # Добавляет сканирование в историю
        self.scan_history.append({
            'timestamp': time.time(),
            'url': url,
            'vulnerabilities_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        })
        # Сохранение в LocalStorage
        self.page.client_storage.set('scan_history', self.scan_history)

    # Проверяет доступность сайта
    def check_site_availability(self, url: str) -> tuple[bool, str]:
        """Проверяет доступность сайта"""
        try:
            # Показываем что идет проверка
            self.progress_text.value = "Проверка..."
            self.page.update()

            # Добавляем User-Agent чтобы избежать блокировки
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            # Добавляем таймаут 10 секунд
            response = requests.get(url, timeout=10, verify=False)

            if response.status_code == 200:
                return True, "✅ Сайт доступен"
            else:
                return False, f"❌ Сайт недоступен (код: {response.status_code})"

        except requests.exceptions.ConnectionError:
            return False, "❌ Не удалось подключиться к сайту"
        except requests.exceptions.Timeout:
            return False, "❌ Таймаут подключения (10 сек)"
        except requests.exceptions.MissingSchema:
            return False, "❌ Неправильный формат URL"
        except requests.exceptions.InvalidURL:
            return False, "❌ Некорректный URL"
        except requests.exceptions.RequestException as e:
            return False, f"❌ Ошибка подключения: {str(e)}"
        except Exception as e:
            return False, f"❌ Неизвестная ошибка: {str(e)}"


    def setup_page(self):
        """Настройка страницы"""
        self.page.window.width = 600
        self.page.window.height = 800
        self.page.window.min_width = 550
        self.page.window.max_width = 800
        self.page.window.min_height = 700
        self.page.window.max_height = 1000
        self.page.window.resizable = False
        self.page.window.title = "Vulnerability Scanner - OWASP ZAP"
        self.page.bgcolor = COLORS["bg_primary"]
        self.page.padding = 20
        self.page.theme_mode = ft.ThemeMode.DARK

    def create_ui(self):
        """Создание интерфейса"""
        # Заголовок
        header = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.SECURITY, color=COLORS["primary"], size=30),
                    ft.Text("Vulnerability Scanner",
                            size=28,
                            weight=ft.FontWeight.BOLD,
                            color=COLORS["text_primary"])
                ], alignment=ft.MainAxisAlignment.CENTER),
                ft.Text("OWASP ZAP Security Testing Tool",
                        size=14,
                        color=COLORS["text_secondary"],
                        text_align=ft.TextAlign.CENTER)
            ], spacing=5),
            margin=ft.margin.only(bottom=20)
        )

        self.scanning_indicator = ft.ProgressRing(
            visible=False, color=COLORS['primary'], stroke_width=3
        )

        # Поле ввода URL
        self.url_field = ft.TextField(
            label="URL для сканирования",
            hint_text="https://example.com",
            prefix_icon=ft.Icons.LINK,
            border_color=COLORS["primary"],
            focused_border_color=COLORS["secondary"],
            cursor_color=COLORS["primary"],
            text_style=ft.TextStyle(color=COLORS["text_primary"]),
            label_style=ft.TextStyle(color=COLORS["text_secondary"]),
            hint_style=ft.TextStyle(color=COLORS["text_secondary"]),
            on_submit=self.start_scan,
            expand=True
        )
        # Выбор глубины сканирования
        self.scan_mode = ft.Dropdown(
            label="Глубина сканирования",
            hint_text="Выберите глубину",
            options=[
                ft.dropdown.Option("fast", "Быстрое (3-5 мин)"),
                ft.dropdown.Option("medium", "Стандартное (5-10 мин)"),
                ft.dropdown.Option("deep", "Полное (10-25 мин)"),
            ],
            value="fast",
            border_color=COLORS["primary"],
            focused_border_color=COLORS["secondary"],
            text_style=ft.TextStyle(color=COLORS["text_primary"]),
            label_style=ft.TextStyle(color=COLORS["text_secondary"]),
            expand=True
        )

        # Кнопка сканирования
        self.scan_button = ft.ElevatedButton(
            content=ft.Row([
                ft.Icon(ft.Icons.PLAY_ARROW, color=COLORS["bg_primary"]),
                ft.Text("Начать сканирование", color=COLORS["bg_primary"], weight=ft.FontWeight.BOLD)
            ], alignment=ft.MainAxisAlignment.CENTER),
            on_click=self.start_scan,
            style=ft.ButtonStyle(
                bgcolor=COLORS["primary"],
                color=COLORS["bg_primary"],
                padding=20,
                overlay_color=COLORS["secondary"],
            ),
            expand=True
        )

        # Прогресс
        self.progress_bar = ft.ProgressBar(
            value=0,
            color=COLORS["primary"],
            bgcolor=COLORS["bg_card"]
        )

        self.status_text = ft.Text("Готов к сканированию", size=16, color=COLORS["text_secondary"])
        self.progress_text = ft.Text("", size=18, weight=ft.FontWeight.BOLD, color=COLORS["primary"])
        self.error_text = ft.Text("", color=COLORS["error"], size=14)

        # Область результатов
        self.results_area = ft.Column(
            scroll=ft.ScrollMode.ADAPTIVE,
            spacing=10,
            expand=True
        )

        # Кнопка справки
        self.help_icon = ft.IconButton(
            icon=ft.Icons.HELP_OUTLINE,
            icon_color=COLORS["text_secondary"],
            tooltip='Справка',
            on_click=self.show_help
        )

        # Основной контейнер
        main_card = ft.Card(
            content=ft.Container(
                content=ft.Column([
                    # Заголовок и кнопка справки
                    ft.Row([
                        ft.Container(expand=True),
                        self.help_icon
                    ]),
                    header,

                    # Поле ввода
                    ft.Container(
                        content=ft.Column([
                            # ft.Text("Цель сканирования:", color=COLORS["text_primary"], size=16),
                            self.url_field,
                            ft.Container(height=5),
                            # ft.Text('Режим работы:', color=COLORS['text_primary'], size=16),
                            self.scan_mode
                        ], spacing=10)
                    ),

                    # Кнопка и прогресс
                    ft.Container(
                        content=ft.Column([
                            self.scan_button,
                            ft.Container(height=10),
                            self.progress_bar,
                            ft.Row([self.status_text, ft.Container(expand=True), self.progress_text]),
                            self.error_text
                        ], spacing=5)
                    ),

                    ft.Divider(color=COLORS["bg_card"], height=10),

                    # Результаты
                    ft.Container(
                        content=ft.Column([
                            ft.Row([
                                ft.Icon(ft.Icons.FIND_IN_PAGE, color=COLORS["primary"]),
                                ft.Text("Результаты сканирования",
                                        size=20,
                                        color=COLORS["text_primary"],
                                        weight=ft.FontWeight.BOLD)
                            ]),
                            ft.Container(
                                content=self.results_area,
                                height=300
                            )
                        ], spacing=15)
                    )
                ], spacing=20),
                padding=30,
                bgcolor=COLORS["bg_card"],
                border_radius=15
            ),
            elevation=10
        )

        # Добавляем на страницу
        self.page.add(
            ft.Column([
                main_card
            ], expand=True)
        )

    def show_help(self, e):
        dlg = ft.AlertDialog(
            title=ft.Text('Справка'),
            content=ft.Text(help_text, selectable=True),
            actions=[ft.TextButton('Закрыть', on_click=lambda e: self.page.close(dlg))],
            actions_alignment=ft.MainAxisAlignment.END
        )
        self.page.open(dlg)

    def close_dialog(self, dlg):
        """Закрытие диалога"""
        dlg.open = False
        self.page.update()

    def show_error(self, message: str):
        self.error_text.value = message
        self.page.update()

    def validate_url(self, url: str) -> bool:
        if not url:
            self.show_error("Поле URL не может быть пустым")
            return False
        if not url.startswith(("http://", "https://")):
            self.show_error("URL должен начинаться с http:// или https://")
            return False

        try:
            from urllib.parse import urlparse
            import re
            parsed = urlparse(url)

            if not parsed.netloc:
                self.show_error('Некорректный формат URL')
                return False

            local_host = ['localhost', '127.0.0.1', '192.168.', '172.16.']
            if any(host in parsed.netloc for host in local_host):
                self.show_error('Сканирование локальных адресов запрещено')
                return False

            # Проверка домена (базовая)
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(domain_pattern, parsed.netloc):
                self.show_error("❌ Некорректный формат домена")
                return False

        except Exception as e:
            self.show_error(f"Ошибка обработки: {e}")
            return False
        return True

    def clear_results(self):
        self.results_area.controls.clear()
        # Получаем текущий режим для статуса
        scan_mode = self.scan_mode.value
        mode_name = {
            'fast': 'Быстрый',
            'medium': 'Стандартный',
            'deep': 'Полный'
        }
        mode_display = mode_name.get(scan_mode, scan_mode)
        self.status_text.value = f'{mode_display} | Готов к сканированию'
        self.progress_text.value = ""
        self.error_text.value = ""
        self.progress_bar.value = 0
        self.page.update()

    def update_progress(self, stage: str, percent: int):
        """Обновляет прогресс в UI"""
        stage_names = {
            "spider": "🕷️ Обход структуры сайта",
            "ascan": "⚔ Активное сканирование уязвимостей"
        }
        # Получаем текущий режим для показа процента прогресса
        scan_mode = self.scan_mode.value
        mode_name = {
            'fast': 'Быстрый',
            'medium': 'Стандартный',
            'deep': 'Полный'
        }
        mode_display = mode_name.get(scan_mode, scan_mode)
        self.status_text.value = f'{mode_display} | {stage_names.get(stage, "Сканирование")}'
        self.progress_text.value = f"{percent}%"
        self.progress_bar.value = percent / 100
        self.page.update()

    def add_result(self, vuln: dict):
        """Добавляет уязвимость в список результатов"""
        risk_colors = {
            "High": COLORS["error"],
            "Medium": COLORS["warning"],
            "Low": COLORS["secondary"],
            "Informational": COLORS["text_secondary"]
        }

        color = risk_colors.get(vuln["risk"], COLORS["text_secondary"])
        risk_icon = ft.Icon(ft.Icons.WARNING, color=color, size=16)

        card = ft.Card(
            content=ft.Container(
                content=ft.Column([
                    ft.Row([
                        risk_icon,
                        ft.Text(f"{vuln['name'][:50]}",
                                weight="bold",
                                color=color,
                                size=13,
                                expand=True),
                        ft.Container(
                            content=ft.Text(vuln['risk'], color=color, weight="bold", size=10),
                            bgcolor=ft.Colors.with_opacity(0.2, color),
                            padding=ft.padding.symmetric(horizontal=6, vertical=2),
                            border_radius=4
                        )
                    ]),
                    ft.Text(f"URL: {vuln['url']}",
                            size=12,
                            color=COLORS["text_secondary"]),
                    ft.Text(vuln['description'][:150] + "...",
                            size=9,
                            color=COLORS["text_secondary"])
                ], spacing=6),
                padding=10,
                bgcolor=ft.Colors.with_opacity(0.05, color)
            ),
            elevation=1
        )
        self.results_area.controls.append(card)
        self.page.update()

    def open_report(self, report_path: str):
        if os.path.exists(report_path):
            webbrowser.open(f"file://{os.path.abspath(report_path)}")

    def start_scan(self, e):
        self.scanning_indicator.visible = True
        self.page.update()
        self.clear_results()
        url = self.url_field.value.strip()
        scan_mode = self.scan_mode.value  # Получаем выбранный режим сканирования


        if not self.validate_url(url):
            return

        # ПРОВЕРКА ДОСТУПНОСТИ САЙТА
        self.status_text.value = "🔍 Проверка доступности сайта..."
        self.page.update()

        is_available, message = self.check_site_availability(url)
        if not is_available:
            self.show_error(message)
            self.scanning_indicator.visible = False
            self.status_text.value = "❌ Сайт недоступен"
            return

        # Если сайт доступен, продолжаем сканирование
        self.status_text.value = "✅ Сайт доступен, запуск сканирования..."
        self.page.update()

        # Блокируем UI
        self.scan_button.disabled = True
        self.url_field.disabled = True
        self.scan_mode.disabled = True
        self.scan_button.content.controls[1].value = "Сканирование..."
        self.page.update()

        try:
            scanner = ZapScanner()
            if not scanner.is_ready():
                self.show_error("❌ ZAP не запущен! Выполните: docker-compose up -d")
                return

            # Запуск сканирования
            vulnerabilities = scanner.scan(url, on_progress=self.update_progress, scan_mode=scan_mode)

            # Генерация отчёта
            report_path = generate_html_report()
            self.status_text.value = f"✅ Сканирование завершено"
            self.progress_text.value = "100%"

            # Кнопка открытия отчёта
            report_btn = ft.FilledButton(
                content=ft.Row([
                    ft.Icon(ft.Icons.ARTICLE, color=COLORS["bg_primary"]),
                    ft.Text("Открыть полный отчёт", color=COLORS["primary"])
                ]),
                on_click=lambda e: self.open_report(report_path),
                style=ft.ButtonStyle(bgcolor=COLORS["success"])
            )
            self.results_area.controls.append(report_btn)

            # Отображение результатов
            if not vulnerabilities:
                self.results_area.controls.append(
                    ft.Container(
                        content=ft.Row([
                            ft.Icon(ft.Icons.CHECK_CIRCLE, color=COLORS["success"]),
                            ft.Text("✅ Уязвимостей не найдено", color=COLORS["success"])
                        ]),
                        padding=15
                    )
                )
            else:
                risk_status = {}
                for vuln in vulnerabilities:
                    risk = vuln['risk']
                    risk_status[risk] = risk_status.get(risk, 0) + 1

                stats_text = " | ".join([f"{risk}: {count}" for risk, count in risk_status.items()])
                self.results_area.controls.append(
                    ft.Container(
                        content=ft.Text(f'Найдено {len(vulnerabilities)} уязвимостей ({stats_text})',
                                        color=COLORS["text_primary"]),
                        bgcolor=COLORS['bg_card'],
                        padding=10,
                        border_radius=5
                    )
                )
                for vuln in vulnerabilities[:15]:
                    self.add_result(vuln)



        except Exception as ex:
            self.show_error(f"💥 Ошибка: {str(ex)}")
        finally:
            # Разблокируем UI
            self.scanning_indicator.visible = False
            self.scan_button.disabled = False
            self.url_field.disabled = False
            self.scan_mode.disabled = False
            self.scan_button.content.controls[1].value = "Начать сканирование"
            self.page.update()


def main(page: ft.Page):
    VulnerabilityScannerUI(page)


if __name__ == "__main__":
    ft.app(
        target=main,
        view=ft.AppView.FLET_APP,
    )