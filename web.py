import os
from flask import Flask, render_template_string
from rich.console import Console
import urllib3

console = Console()
app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string("""
        <h2>✅ API lấy mã & tạo KEY đang hoạt động!</h2>
        <p>Muốn sử dụng phải xác nhận KEY!</p>
    """)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    console.print(f"[green]🚀 Flask đang chạy trên port {port}...[/green]")
    app.run(host="0.0.0.0", port=port, threaded=True)