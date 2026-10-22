"""
xssentry/desktop.py

Native Desktop Application window for XSSentry.
Embeds the rich cybersecurity web dashboard into a native GUI desktop application
using PyQt6 QWebEngineView with automatic fallback to standalone App-mode browser.
"""

import os
import socket
import sys
import threading
import time
from typing import Optional

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiohttp import web
from xssentry.app import create_app


def find_free_port(default_port: int = 8888) -> int:
    """Find a free port, preferring default_port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", default_port))
            return default_port
        except OSError:
            pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_server_thread(host: str, port: int) -> None:
    """Run the aiohttp server in a dedicated background thread."""
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    app = create_app()
    runner = web.AppRunner(app)
    loop.run_until_complete(runner.setup())
    site = web.TCPSite(runner, host, port)
    loop.run_until_complete(site.start())
    loop.run_forever()


def launch_pyqt_desktop(url: str, title: str = "XSSentry — Autonomous XSS Hunter [HELLHOUND v5]") -> bool:
    """Launch the native PyQt6 WebEngine desktop window."""
    try:
        from PyQt6.QtCore import QUrl, Qt
        from PyQt6.QtGui import QIcon, QKeySequence, QShortcut
        from PyQt6.QtWebEngineCore import QWebEngineSettings
        from PyQt6.QtWebEngineWidgets import QWebEngineView
        from PyQt6.QtWidgets import QApplication, QMainWindow
    except ImportError as e:
        print(f"[*] PyQt6 not available: {e}")
        return False

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("XSSentry")

    # Set application & window icon
    icon_candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Image", "logo.png"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "static", "img", "logo.png"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "static", "img", "logo.jpg"),
    ]
    app_icon = None
    for icon_path in icon_candidates:
        if os.path.exists(icon_path):
            app_icon = QIcon(icon_path)
            if not app_icon.isNull():
                break

    if app_icon and not app_icon.isNull():
        app.setWindowIcon(app_icon)

    window = QMainWindow()
    window.setWindowTitle(title)
    if app_icon and not app_icon.isNull():
        window.setWindowIcon(app_icon)
    window.resize(1340, 880)
    window.setMinimumSize(1000, 650)

    # Web view widget
    view = QWebEngineView(window)
    settings = view.settings()
    settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
    settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, True)
    settings.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, True)
    settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)

    view.setUrl(QUrl(url))
    window.setCentralWidget(view)

    # F12 developer tools shortcut
    def toggle_dev_tools():
        from PyQt6.QtWebEngineWidgets import QWebEngineView
        if not hasattr(window, "dev_view") or window.dev_view is None:
            window.dev_view = QWebEngineView()
            view.page().setDevToolsPage(window.dev_view.page())
            window.dev_view.setWindowTitle("XSSentry Developer Tools")
            window.dev_view.resize(900, 600)
        window.dev_view.show()

    shortcut_f12 = QShortcut(QKeySequence("F12"), window)
    shortcut_f12.activated.connect(toggle_dev_tools)

    # F5 reload shortcut
    shortcut_f5 = QShortcut(QKeySequence("F5"), window)
    shortcut_f5.activated.connect(view.reload)

    window.show()
    app.exec()
    return True


def launch_standalone_browser_app(url: str) -> bool:
    """Fallback: launch browser in standalone application window mode without URL bar."""
    import subprocess
    import shutil

    browsers = [
        ("chromium", ["chromium", f"--app={url}", "--class=XSSentry", "--name=XSSentry"]),
        ("google-chrome", ["google-chrome", f"--app={url}", "--class=XSSentry"]),
        ("brave-browser", ["brave-browser", f"--app={url}"]),
        ("edge", ["microsoft-edge", f"--app={url}"]),
    ]

    for name, cmd in browsers:
        if shutil.which(name):
            try:
                print(f"[*] Launching desktop app via {name} application mode...")
                subprocess.Popen(cmd)
                return True
            except Exception:
                continue

    return False


def start_desktop(target_url: Optional[str] = None, port: int = 8888) -> None:
    """Main desktop launcher: starts background server and GUI window."""
    free_port = find_free_port(port)
    host = "127.0.0.1"
    app_url = f"http://{host}:{free_port}"

    print(f"[*] 🛡️ Starting XSSentry Desktop Engine on {app_url}...")

    # Start backend server in daemon thread
    server_thread = threading.Thread(target=run_server_thread, args=(host, free_port), daemon=True)
    server_thread.start()

    # Wait for server to bind
    time.sleep(0.5)

    # Set initial target if provided
    if target_url:
        from xssentry.app import state
        state.set_target(target_url)

    # Try native PyQt6 window first
    print("[*] Launching native Desktop window...")
    launched = launch_pyqt_desktop(app_url)

    if not launched:
        # Fallback to browser app mode
        print("[*] Falling back to standalone desktop app mode...")
        launched = launch_standalone_browser_app(app_url)

    if not launched:
        import webbrowser
        print("[*] Falling back to default browser...")
        webbrowser.open(app_url)
        # Keep server thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nExiting.")


if __name__ == "__main__":
    start_desktop()
