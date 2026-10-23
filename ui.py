"""Окно хранилища паролей."""

import os
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox, ttk

import pyperclip

import db
from crypto import (
    DEFAULT_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    CryptoError,
    decrypt_password,
    encrypt_password,
    generate_password,
    hash_master_password,
    verify_master_password,
)

FIELD = "#D7E0DA"
SHEET = "#F6F7F4"
INK = "#1A2420"
STAMP = "#1E4F45"
STAMP_ACTIVE = "#163E37"
LINE = "#C5D0CB"
MUTED = "#5E6E68"
DANGER = "#8E3D36"
WHITE = "#FFFFFF"


def choose_font(size: int, weight: str = "normal", prefer: str = "Segoe UI"):
    families = set(tkfont.families())
    if prefer not in families:
        prefer = "Segoe UI" if "Segoe UI" in families else "TkDefaultFont"
    if weight == "normal":
        return (prefer, size)
    return (prefer, size, weight)


def copy_text(value: str) -> bool:
    try:
        pyperclip.copy(value)
    except pyperclip.PyperclipException:
        return False
    return True


class VaultApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Хранилище паролей")
        self.root.configure(bg=FIELD)
        self.root.minsize(420, 320)
        self.title_font = choose_font(26, prefer="Constantia")
        self.body_font = choose_font(11)
        self.small_font = choose_font(10)
        self.mono_font = choose_font(12, prefer="Consolas")
        self._style_tree()
        self.attempts = 0
        if db.get_master_hash() is None:
            self.show_setup()
        else:
            self.show_login()

    def _style_tree(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Vault.Treeview",
            background=WHITE,
            fieldbackground=WHITE,
            foreground=INK,
            borderwidth=0,
            relief="flat",
            rowheight=34,
            font=self.body_font,
        )
        style.configure(
            "Vault.Treeview.Heading",
            background=SHEET,
            foreground=MUTED,
            relief="flat",
            font=self.small_font,
        )
        style.map(
            "Vault.Treeview",
            background=[("selected", STAMP)],
            foreground=[("selected", SHEET)],
        )
        style.layout("Vault.Treeview", style.layout("Treeview"))

    def clear(self) -> None:
        for child in self.root.winfo_children():
            child.destroy()

    def show_setup(self) -> None:
        self.clear()
        self.root.geometry("460x420")
        self._place_center(460, 420)
        frame = self._sheet(self.root)
        tk.Label(frame, text="Новое хранилище", bg=SHEET, fg=INK, font=self.title_font).pack(
            anchor="w"
        )
        tk.Label(
            frame,
            text="Этот пароль открывает программу. Он сохранится как хеш, не как текст.",
            bg=SHEET,
            fg=MUTED,
            font=self.small_font,
            wraplength=360,
            justify="left",
        ).pack(anchor="w", pady=(8, 18))
        self.setup_password = self._secret_field(frame, "Мастер-пароль")
        self.setup_confirm = self._secret_field(frame, "Повторите мастер-пароль")
        self.setup_status = self._status(frame)
        self._button(frame, "Создать хранилище", self.create_master, primary=True).pack(
            anchor="w", pady=(8, 0)
        )
        self.setup_password.focus_set()
        self.root.bind("<Return>", lambda _event: self.create_master())

    def show_login(self) -> None:
        self.clear()
        self.root.geometry("460x360")
        self._place_center(460, 360)
        frame = self._sheet(self.root)
        tk.Label(frame, text="Хранилище", bg=SHEET, fg=INK, font=self.title_font).pack(anchor="w")
        tk.Label(
            frame,
            text="Введите мастер-пароль, чтобы открыть записи.",
            bg=SHEET,
            fg=MUTED,
            font=self.small_font,
        ).pack(anchor="w", pady=(8, 18))
        self.login_password = self._secret_field(frame, "Мастер-пароль")
        self.login_status = self._status(frame)
        self.login_button = self._button(frame, "Войти", self.login, primary=True)
        self.login_button.pack(anchor="w", pady=(8, 0))
        self.login_password.focus_set()
        self.root.bind("<Return>", lambda _event: self.login())

    def show_main(self) -> None:
        self.clear()
        self.root.unbind("<Return>")
        self.root.minsize(720, 480)
        self.root.geometry("820x540")
        self._place_center(820, 540)

        spine = tk.Frame(self.root, bg=STAMP, width=12)
        spine.pack(side="left", fill="y")
        body = tk.Frame(self.root, bg=FIELD)
        body.pack(side="left", fill="both", expand=True)

        header = tk.Frame(body, bg=FIELD)
        header.pack(fill="x", padx=28, pady=(22, 8))
        tk.Label(header, text="Хранилище", bg=FIELD, fg=INK, font=self.title_font).pack(anchor="w")
        tk.Label(
            header,
            text="Название и логин видны в списке. Пароль открывается отдельно.",
            bg=FIELD,
            fg=MUTED,
            font=self.small_font,
        ).pack(anchor="w", pady=(4, 0))

        toolbar = tk.Frame(body, bg=FIELD)
        toolbar.pack(fill="x", padx=28, pady=(12, 8))
        tk.Label(toolbar, text="Название", bg=FIELD, fg=INK, font=self.body_font).pack(side="left")
        self.search_var = tk.StringVar()
        search = self._entry(toolbar, self.search_var)
        search.pack(side="left", padx=(8, 12), fill="x", expand=True)
        search.bind("<KeyRelease>", lambda _event: self.refresh_list())
        search.bind("<Return>", lambda _event: self.open_selected())
        self._button(toolbar, "Новая запись", self.open_add, primary=True).pack(side="left")

        table_wrap = tk.Frame(body, bg=WHITE, highlightbackground=LINE, highlightthickness=1)
        table_wrap.pack(fill="both", expand=True, padx=28, pady=(4, 8))
        columns = ("name", "login")
        self.tree = ttk.Treeview(
            table_wrap,
            columns=columns,
            show="headings",
            style="Vault.Treeview",
            selectmode="browse",
        )
        self.tree.heading("name", text="Название", anchor="w")
        self.tree.heading("login", text="Логин", anchor="w")
        self.tree.column("name", width=240, anchor="w")
        self.tree.column("login", width=360, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=1, pady=1)
        self.tree.bind("<Double-1>", lambda _event: self.open_selected())
        self.tree.bind("<Return>", lambda _event: self.open_selected())

        self.empty_label = tk.Label(
            table_wrap,
            text="Записей пока нет. Добавьте первую — пароль соберётся сам.",
            bg=WHITE,
            fg=MUTED,
            font=self.body_font,
        )

        actions = tk.Frame(body, bg=FIELD)
        actions.pack(fill="x", padx=28, pady=(4, 4))
        self._button(actions, "Открыть", self.open_selected).pack(side="left")
        self._button(actions, "Удалить", self.delete_selected).pack(side="left", padx=(8, 0))
        self._button(actions, "Новый пароль", self.open_generator).pack(side="right")

        self.main_status = tk.Label(body, text="", bg=FIELD, fg=STAMP, font=self.small_font, anchor="w")
        self.main_status.pack(fill="x", padx=28, pady=(4, 16))
        self.refresh_list()

    def create_master(self) -> None:
        password = self.setup_password.get()
        confirm = self.setup_confirm.get()
        if not password:
            self.setup_status.config(text="Введите мастер-пароль.")
            return
        if password != confirm:
            self.setup_status.config(text="Пароли не совпадают.")
            return
        db.set_master_hash(hash_master_password(password))
        self.show_main()
        self.set_status("Хранилище создано.")

    def login(self) -> None:
        if not self.login_button.winfo_exists() or str(self.login_button["state"]) == "disabled":
            return
        stored = db.get_master_hash()
        if stored and verify_master_password(self.login_password.get(), stored):
            self.attempts = 0
            self.show_main()
            return
        self.attempts += 1
        left = 3 - self.attempts
        self.login_password.delete(0, "end")
        if left <= 0:
            self.login_status.config(text="Слишком много неверных попыток.")
            self.login_button.configure(state="disabled")
            self.login_password.configure(state="disabled")
            return
        self.login_status.config(text=f"Неверный мастер-пароль. Осталось попыток: {left}.")

    def refresh_list(self) -> None:
        query = self.search_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        rows = [
            row
            for row in db.list_entries()
            if not query or query in str(row["name"]).lower() or query in str(row["login"]).lower()
        ]
        for row in rows:
            self.tree.insert("", "end", iid=str(row["name"]), values=(row["name"], row["login"]))
        if rows:
            self.empty_label.place_forget()
        else:
            self.empty_label.place(relx=0.5, rely=0.55, anchor="center")
            self.empty_label.lift()

    def selected_name(self):
        selected = self.tree.selection()
        if selected:
            return str(self.tree.item(selected[0], "values")[0])
        query = self.search_var.get().strip().lower()
        if not query:
            return None
        matches = [row for row in db.list_entries() if str(row["name"]).lower() == query]
        if len(matches) == 1:
            return str(matches[0]["name"])
        return None

    def open_selected(self) -> None:
        name = self.selected_name()
        if not name:
            self.set_status("Выберите запись в списке.")
            return
        self.show_entry(name)

    def delete_selected(self) -> None:
        name = self.selected_name()
        if not name:
            self.set_status("Выберите запись, которую нужно удалить.")
            return
        self.delete_entry(name)

    def delete_entry(self, name: str) -> None:
        if not messagebox.askyesno(
            "Удалить запись",
            f"Удалить «{name}» из хранилища?",
            parent=self.root,
        ):
            return
        if db.delete_entry(name):
            self.refresh_list()
            self.set_status(f"Запись «{name}» удалена.")
            return
        self.set_status(f"Запись «{name}» не найдена.")

    def open_add(self) -> None:
        dialog = EntryDialog(self)
        self.root.wait_window(dialog)
        if dialog.saved_name:
            self.refresh_list()
            self.set_status(f"Запись «{dialog.saved_name}» сохранена.")

    def open_generator(self) -> None:
        dialog = GeneratorDialog(self.root, self, save_record=False)
        self.root.wait_window(dialog)

    def show_entry(self, name: str) -> None:
        entry = db.get_entry(name)
        if entry is None:
            self.set_status(f"Запись «{name}» не найдена.")
            self.refresh_list()
            return
        try:
            password = decrypt_password(str(entry["password"]))
        except CryptoError as exc:
            messagebox.showerror("Хранилище", str(exc), parent=self.root)
            return
        dialog = RecordDialog(self, str(entry["name"]), str(entry["login"]), password)
        self.root.wait_window(dialog)
        if dialog.deleted:
            self.refresh_list()
            self.set_status(f"Запись «{entry['name']}» удалена.")

    def set_status(self, text: str) -> None:
        if hasattr(self, "main_status") and self.main_status.winfo_exists():
            self.main_status.config(text=text)

    def _place_center(self, width: int, height: int) -> None:
        self.root.update_idletasks()
        x = max(0, (self.root.winfo_screenwidth() - width) // 2)
        y = max(0, (self.root.winfo_screenheight() - height) // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _sheet(self, parent: tk.Widget) -> tk.Frame:
        outer = tk.Frame(parent, bg=FIELD)
        outer.pack(fill="both", expand=True)
        spine = tk.Frame(outer, bg=STAMP, width=12)
        spine.pack(side="left", fill="y")
        card = tk.Frame(outer, bg=SHEET, padx=28, pady=26)
        card.pack(side="left", fill="both", expand=True, padx=(0, 18), pady=18)
        return card

    def _secret_field(self, parent: tk.Widget, label: str) -> tk.Entry:
        tk.Label(parent, text=label, bg=SHEET, fg=INK, font=self.body_font).pack(anchor="w")
        entry = tk.Entry(
            parent,
            show="•",
            font=self.body_font,
            bg=WHITE,
            fg=INK,
            relief="flat",
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=STAMP,
            insertbackground=INK,
        )
        entry.pack(fill="x", ipady=6, pady=(4, 12))
        return entry

    def _entry(self, parent: tk.Widget, variable: tk.StringVar) -> tk.Entry:
        return tk.Entry(
            parent,
            textvariable=variable,
            font=self.body_font,
            bg=WHITE,
            fg=INK,
            relief="flat",
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=STAMP,
            insertbackground=INK,
        )

    def _status(self, parent: tk.Widget) -> tk.Label:
        label = tk.Label(parent, text="", bg=SHEET, fg=DANGER, font=self.small_font, anchor="w")
        label.pack(fill="x", pady=(0, 4))
        return label

    def _button(self, parent: tk.Widget, text: str, command, primary: bool = False) -> tk.Button:
        if primary:
            bg, fg, active = STAMP, SHEET, STAMP_ACTIVE
        else:
            bg, fg, active = SHEET, INK, "#E4EBE7"
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active,
            activeforeground=fg,
            relief="flat",
            bd=0,
            padx=14,
            pady=7,
            font=self.body_font,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground=STAMP if primary else LINE,
            highlightcolor=STAMP,
        )
        return button


class GeneratorDialog(tk.Toplevel):
    def __init__(self, parent: tk.Widget, app: VaultApp, save_record: bool):
        super().__init__(parent)
        self.app = app
        self.save_record = save_record
        self.saved_name = ""
        self.title("Новая запись" if save_record else "Новый пароль")
        self.configure(bg=SHEET)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.name_var = tk.StringVar()
        self.login_var = tk.StringVar()
        self.length_var = tk.IntVar(value=DEFAULT_PASSWORD_LENGTH)
        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.special_var = tk.BooleanVar(value=True)
        self.password_var = tk.StringVar()
        self._regen_job = None

        form = tk.Frame(self, bg=SHEET, padx=24, pady=20)
        form.pack(fill="both", expand=True)
        tk.Label(
            form,
            text="Новая запись" if save_record else "Новый пароль",
            bg=SHEET,
            fg=INK,
            font=app.title_font,
        ).pack(anchor="w")
        hint = (
            "Пароль соберётся сам. Его можно скопировать и сохранить."
            if save_record
            else "Пароль только для копирования, в список он не попадёт."
        )
        tk.Label(form, text=hint, bg=SHEET, fg=MUTED, font=app.small_font).pack(anchor="w", pady=(4, 14))

        if save_record:
            self._labeled_entry(form, "Название", self.name_var)
            self._labeled_entry(form, "Логин", self.login_var)

        options = tk.Frame(form, bg=SHEET)
        options.pack(fill="x", pady=(4, 8))
        tk.Label(options, text="Длина", bg=SHEET, fg=INK, font=app.body_font).grid(row=0, column=0, sticky="w")
        length = tk.Spinbox(
            options,
            from_=1,
            to=MAX_PASSWORD_LENGTH,
            textvariable=self.length_var,
            width=6,
            font=app.body_font,
            bg=WHITE,
            fg=INK,
            relief="flat",
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=STAMP,
            buttonbackground=SHEET,
            justify="center",
            command=self.regenerate,
        )
        length.grid(row=0, column=1, padx=(8, 16))
        tk.Label(
            options,
            text=f"до {MAX_PASSWORD_LENGTH}",
            bg=SHEET,
            fg=MUTED,
            font=app.small_font,
        ).grid(row=0, column=2, sticky="w")

        checks = tk.Frame(form, bg=SHEET)
        checks.pack(fill="x", pady=(4, 10))
        for index, (text, variable) in enumerate(
            (
                ("Заглавные буквы", self.upper_var),
                ("Строчные буквы", self.lower_var),
                ("Цифры", self.digits_var),
                ("Спецсимволы", self.special_var),
            )
        ):
            tk.Checkbutton(
                checks,
                text=text,
                variable=variable,
                command=self.regenerate,
                bg=SHEET,
                fg=INK,
                activebackground=SHEET,
                activeforeground=INK,
                selectcolor=WHITE,
                font=app.body_font,
                anchor="w",
            ).grid(row=index // 2, column=index % 2, sticky="w", padx=(0, 18), pady=2)

        tk.Label(form, text="Пароль", bg=SHEET, fg=INK, font=app.body_font).pack(anchor="w")
        preview = tk.Entry(
            form,
            textvariable=self.password_var,
            font=app.mono_font,
            bg=WHITE,
            fg=INK,
            relief="flat",
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=STAMP,
            state="readonly",
            readonlybackground=WHITE,
        )
        preview.pack(fill="x", ipady=6, pady=(4, 8))

        self.form_status = tk.Label(form, text="", bg=SHEET, fg=DANGER, font=app.small_font, anchor="w")
        self.form_status.pack(fill="x")

        buttons = tk.Frame(form, bg=SHEET)
        buttons.pack(fill="x", pady=(12, 0))
        app._button(buttons, "Другой пароль", self.regenerate).pack(side="left")
        app._button(buttons, "Копировать", self.copy_password).pack(side="left", padx=(8, 0))
        if save_record:
            app._button(buttons, "Сохранить", self.save, primary=True).pack(side="right")
        else:
            app._button(buttons, "Закрыть", self.destroy).pack(side="right")

        self.length_var.trace_add("write", lambda *_args: self.schedule_regenerate())
        self.bind("<Escape>", lambda _event: self.destroy())
        self.regenerate()
        self.update_idletasks()
        width = max(self.winfo_reqwidth(), 560)
        height = self.winfo_reqheight()
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        if os.environ.get("VAULT_TEST") == "1":
            self.withdraw()

    def destroy(self) -> None:
        if self._regen_job is not None:
            try:
                self.after_cancel(self._regen_job)
            except tk.TclError:
                pass
            self._regen_job = None
        super().destroy()

    def schedule_regenerate(self) -> None:
        if self._regen_job is not None:
            try:
                self.after_cancel(self._regen_job)
            except tk.TclError:
                pass
        self._regen_job = self.after(180, self.regenerate)

    def regenerate(self) -> None:
        self._regen_job = None
        try:
            length = int(self.length_var.get())
        except (tk.TclError, ValueError):
            self.form_status.config(
                text=f"Длина — число от 1 до {MAX_PASSWORD_LENGTH}.",
                fg=DANGER,
            )
            return
        try:
            password = generate_password(
                length,
                bool(self.upper_var.get()),
                bool(self.lower_var.get()),
                bool(self.digits_var.get()),
                bool(self.special_var.get()),
            )
        except ValueError as exc:
            self.form_status.config(text=str(exc), fg=DANGER)
            return
        self.password_var.set(password)
        self.form_status.config(text="")

    def copy_password(self) -> None:
        password = self.password_var.get()
        if not password:
            self.form_status.config(text="Пароль ещё не собран.")
            return
        if copy_text(password):
            self.form_status.config(text="Пароль скопирован.", fg=STAMP)
            return
        self.form_status.config(text="Буфер обмена недоступен.", fg=DANGER)

    def save(self) -> None:
        name = self.name_var.get().strip()
        login = self.login_var.get().strip()
        password = self.password_var.get()
        if not name or not login:
            self.form_status.config(text="Нужны название и логин.", fg=DANGER)
            return
        if not password:
            self.form_status.config(text="Сначала соберите пароль.", fg=DANGER)
            return
        if db.get_entry(name) is not None:
            self.form_status.config(text=f"Запись «{name}» уже есть.", fg=DANGER)
            return
        db.add_entry(name, login, encrypt_password(password))
        self.saved_name = name
        self.destroy()

    def _labeled_entry(self, parent: tk.Widget, label: str, variable: tk.StringVar) -> None:
        tk.Label(parent, text=label, bg=SHEET, fg=INK, font=self.app.body_font).pack(anchor="w")
        entry = self.app._entry(parent, variable)
        entry.pack(fill="x", ipady=6, pady=(4, 12))

class EntryDialog(GeneratorDialog):
    def __init__(self, app: VaultApp):
        super().__init__(app.root, app, save_record=True)


class RecordDialog(tk.Toplevel):
    def __init__(self, app: VaultApp, name: str, login: str, password: str):
        super().__init__(app.root)
        self.app = app
        self.record_name = name
        self.password = password
        self.deleted = False
        self.title(name)
        self.configure(bg=SHEET)
        self.resizable(False, False)
        self.transient(app.root)
        self.grab_set()

        form = tk.Frame(self, bg=SHEET, padx=24, pady=20)
        form.pack(fill="both", expand=True)
        tk.Label(form, text=name, bg=SHEET, fg=INK, font=app.title_font).pack(anchor="w")
        self._row(form, "Логин", login, app)
        self.password_entry = self._row(form, "Пароль", password, app, mono=True)
        self.visible = True

        self.status = tk.Label(form, text="", bg=SHEET, fg=STAMP, font=app.small_font, anchor="w")
        self.status.pack(fill="x", pady=(4, 0))

        buttons = tk.Frame(form, bg=SHEET)
        buttons.pack(fill="x", pady=(14, 0))
        self.toggle_button = app._button(buttons, "Скрыть", self.toggle)
        self.toggle_button.pack(side="left")
        app._button(buttons, "Копировать пароль", self.copy_password).pack(side="left", padx=(8, 0))
        delete = app._button(buttons, "Удалить", self.delete)
        delete.configure(fg=DANGER, highlightbackground=DANGER)
        delete.pack(side="right")

        self.bind("<Escape>", lambda _event: self.destroy())
        self.update_idletasks()
        width, height = 520, self.winfo_height()
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        if os.environ.get("VAULT_TEST") == "1":
            self.withdraw()

    def _row(self, parent: tk.Widget, label: str, value: str, app: VaultApp, mono: bool = False) -> tk.Entry:
        tk.Label(parent, text=label, bg=SHEET, fg=INK, font=app.body_font).pack(anchor="w", pady=(10, 0))
        variable = tk.StringVar(value=value)
        entry = tk.Entry(
            parent,
            textvariable=variable,
            font=app.mono_font if mono else app.body_font,
            bg=WHITE,
            fg=INK,
            relief="flat",
            highlightthickness=1,
            highlightbackground=LINE,
            highlightcolor=STAMP,
            state="readonly",
            readonlybackground=WHITE,
        )
        entry.pack(fill="x", ipady=6, pady=(4, 0))
        return entry

    def toggle(self) -> None:
        self.visible = not self.visible
        self.password_entry.configure(show="" if self.visible else "•")
        self.toggle_button.configure(text="Скрыть" if self.visible else "Показать")

    def copy_password(self) -> None:
        if copy_text(self.password):
            self.status.config(text="Пароль скопирован.", fg=STAMP)
            return
        self.status.config(text="Буфер обмена недоступен.", fg=DANGER)

    def delete(self) -> None:
        if not messagebox.askyesno(
            "Удалить запись",
            f"Удалить «{self.record_name}» из хранилища?",
            parent=self,
        ):
            return
        if db.delete_entry(self.record_name):
            self.deleted = True
            self.destroy()


def main() -> None:
    root = tk.Tk()
    VaultApp(root)
    root.mainloop()
