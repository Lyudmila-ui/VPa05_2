"""Запуск оконного хранилища паролей."""

import os
import sys


def _guard_stdio() -> None:
    # В режиме без консоли stdout и stderr равны None.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")


def _windows_app_id() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            import ctypes

            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("VPa05.PasswordVault")
    except (AttributeError, OSError):
        pass


def main() -> None:
    _guard_stdio()
    _windows_app_id()

    import db
    from crypto import CryptoError, ensure_key
    from tkinter import messagebox
    import tkinter as tk

    from ui import VaultApp

    try:
        db.init_db()
        ensure_key()
    except CryptoError as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Хранилище", str(exc))
        root.destroy()
        return

    root = tk.Tk()
    VaultApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
