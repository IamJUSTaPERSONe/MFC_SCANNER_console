# core/report.py
import os
import requests
from datetime import datetime

def generate_html_report(output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    filename = f"zap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(output_dir, filename)

    response = requests.get("http://localhost:8080/OTHER/core/other/htmlreport/")
    response.raise_for_status()

    with open(filepath, "wb") as f:
        f.write(response.content)

    return filepath