"""
Инквизитор — модуль локализации (русский / английский).
ShashevPro · https://www.shashevpro.ru/

Вся видимая пользователю строка хранится здесь под ключом. Находки движка
несут только ключ (title_key / rec_key), а человеческий текст подставляется
во время отображения — это позволяет переключать язык на лету.
"""

from __future__ import annotations

LANGUAGES = ("ru", "en")

STRINGS: dict[str, dict[str, str]] = {
    "ru": {
        # --- приложение ---
        "app.name": "Инквизитор",
        "app.tagline": "Сканер скрытых меток в Python-коде",
        # --- интерфейс ---
        "ui.scan": "🔍  Проверить",
        "ui.choose_file": "Выбрать файл",
        "ui.choose_folder": "Выбрать папку",
        "ui.drop_hint": "Перетащите сюда .py-файл или папку с проектом",
        "ui.drop_active": "Отпустите — начнём проверку",
        "ui.scanning": "Идёт проверка…",
        "ui.save_report": "Сохранить отчёт",
        "ui.clean_file": "Очистить файл от меток",
        "ui.reset": "Сбросить",
        "ui.language": "Язык",
        "ui.expand_all": "Развернуть всё",
        "ui.collapse_all": "Свернуть всё",
        "ui.copyright": "© {year} ShashevPro · все права защищены",
        "ui.open_site": "Перейти на сайт ShashevPro",
        # --- сводка ---
        "ui.summary": "Итоги проверки",
        "ui.files_scanned": "Проверено файлов",
        "ui.threats": "Найдено угроз",
        "ui.marks": "Меток автора",
        "ui.issues": "Файлов с замечаниями",
        "ui.no_findings": "Подозрительных элементов не найдено",
        "ui.clean_summary": "{count} файлов без замечаний (нажмите, чтобы показать)",
        "ui.all_clean": "Чисто. Проверено файлов: {count}, замечаний не найдено.",
        "ui.idle": "Готов к работе. Выберите файл или папку.",
        "ui.encoding": "кодировка",
        # --- статусы ---
        "status.green": "Чисто",
        "status.yellow": "Есть замечания",
        "status.red": "Опасность",
        # --- уровни опасности ---
        "sev.info": "инфо",
        "sev.low": "низкая",
        "sev.medium": "средняя",
        "sev.high": "высокая",
        "sev.critical": "критическая",
        # --- сообщения ---
        "msg.no_py_files": "В выбранной папке не найдено .py-файлов.",
        "msg.cleaned": "Удалено невидимых символов: {count}. Сохранено: {path}",
        "msg.clean_nothing": "Невидимых символов не найдено — чистить нечего.",
        "msg.report_saved": "Отчёт сохранён: {path}",
        "msg.mark_copied": "Метка скопирована в буфер обмена.",
        "msg.pick_first": "Сначала выберите файл или папку.",
        "msg.clean_one_file": "Очистка работает только для одного файла.",
        # --- находки ---
        "finding.zero_width": "Невидимый символ нулевой ширины",
        "finding.bidi": "Управление направлением текста (Trojan Source)",
        "finding.tag": "Скрытый tag-символ (ASCII-контрабанда)",
        "finding.variation_selector": "Селектор начертания (носитель payload)",
        "finding.emoji_selector": "Селектор отображения эмодзи (норма)",
        "finding.pua": "Символ приватной зоны (Private Use Area)",
        "finding.invisible_format": "Невидимый форматирующий символ",
        "finding.control": "Управляющий символ",
        "finding.invisible_run": "Цепочка невидимых символов",
        "finding.hidden_string": "Расшифрована скрытая строка",
        "finding.author_mark": "Обнаружена метка автора",
        "finding.homoglyph": "Смешанные алфавиты (гомоглиф-подмена)",
        "finding.encoded_string": "Закодированная строка",
        "finding.watermark_dunder": "Водяной знак в коде",
        "finding.watermark_comment": "Метка в комментарии",
        "finding.sensitive_import": "Импорт чувствительной библиотеки",
        "finding.network_call": "Обращение к сети",
        "finding.network_calls": "Сетевые вызовы (норма для сетевых программ)",
        "finding.shell_exec": "Запуск системной команды",
        "finding.shell_execs": "Запуск системных команд",
        "finding.exec_decoded": "exec/eval с декодированием — обфускация!",
        "finding.exec_dynamic": "exec/eval с динамическим аргументом",
        "finding.exec_literal": "Вызов exec/eval/compile",
        "finding.parse_error": "Синтаксис не разобран (AST пропущен)",
        "finding.detector_error": "Сбой детектора",
        # --- секреты ---
        "secret.aws_key": "Ключ доступа AWS",
        "secret.telegram_token": "Токен Telegram-бота",
        "secret.stripe_live": "Боевой ключ Stripe",
        "secret.github_token": "Токен GitHub",
        "secret.github_pat": "Персональный токен GitHub",
        "secret.google_api": "Ключ Google API",
        "secret.slack_token": "Токен Slack",
        "secret.private_key": "Приватный ключ",
        "secret.jwt": "JWT-токен",
        "secret.generic": "Похоже на секрет в коде",
        # --- рекомендации ---
        "rec.invisible": "Невидимые символы в исходнике — аномалия. Проверьте "
                         "цепочку и при необходимости очистите файл.",
        "rec.emoji": "Селектор эмодзи — часть символа эмодзи, обычно безвреден.",
        "rec.hidden_string": "В коде спрятано скрытое сообщение. Изучите его "
                             "содержимое перед запуском файла.",
        "rec.foreign_mark": "Метка принадлежит не вам. Выясните происхождение "
                            "файла.",
        "rec.homoglyph": "Буквы из разных алфавитов в одном слове — частый приём "
                         "маскировки. Сравните с оригиналом.",
        "rec.secret": "Уберите секрет из кода до публикации и смените его.",
        "rec.encoded_string": "Проверьте, что скрывается в закодированной строке.",
        "rec.sensitive_import": "Убедитесь, что библиотека используется законно.",
        "rec.network_call": "Проверьте, куда и зачем код выходит в сеть.",
        "rec.shell_exec": "Запуск команд оболочки опасен — проверьте источник.",
        "rec.dangerous_exec": "Динамическое исполнение кода — классический приём "
                              "вредоносов. Изучите вручную.",
        "rec.parse_error": "Файл не парсится как Python. Проверены только текст и "
                           "невидимые символы.",
    },
    "en": {
        # --- application ---
        "app.name": "Inquisitor",
        "app.tagline": "Hidden-mark scanner for Python code",
        # --- interface ---
        "ui.scan": "🔍  Scan",
        "ui.choose_file": "Choose file",
        "ui.choose_folder": "Choose folder",
        "ui.drop_hint": "Drop a .py file or a project folder here",
        "ui.drop_active": "Release to start scanning",
        "ui.scanning": "Scanning…",
        "ui.save_report": "Save report",
        "ui.clean_file": "Clean file of marks",
        "ui.reset": "Reset",
        "ui.language": "Language",
        "ui.expand_all": "Expand all",
        "ui.collapse_all": "Collapse all",
        "ui.copyright": "© {year} ShashevPro · all rights reserved",
        "ui.open_site": "Open the ShashevPro website",
        # --- summary ---
        "ui.summary": "Scan summary",
        "ui.files_scanned": "Files scanned",
        "ui.threats": "Threats found",
        "ui.marks": "Author marks",
        "ui.issues": "Files with notes",
        "ui.no_findings": "No suspicious elements found",
        "ui.clean_summary": "{count} files with no findings (click to show)",
        "ui.all_clean": "Clean. {count} files scanned, no findings.",
        "ui.idle": "Ready. Choose a file or folder.",
        "ui.encoding": "encoding",
        # --- statuses ---
        "status.green": "Clean",
        "status.yellow": "Has notes",
        "status.red": "Danger",
        # --- severity ---
        "sev.info": "info",
        "sev.low": "low",
        "sev.medium": "medium",
        "sev.high": "high",
        "sev.critical": "critical",
        # --- messages ---
        "msg.no_py_files": "No .py files found in the selected folder.",
        "msg.cleaned": "Invisible characters removed: {count}. Saved: {path}",
        "msg.clean_nothing": "No invisible characters found — nothing to clean.",
        "msg.report_saved": "Report saved: {path}",
        "msg.mark_copied": "Mark copied to clipboard.",
        "msg.pick_first": "Choose a file or folder first.",
        "msg.clean_one_file": "Cleaning works for a single file only.",
        # --- findings ---
        "finding.zero_width": "Zero-width invisible character",
        "finding.bidi": "Bidirectional control (Trojan Source)",
        "finding.tag": "Hidden tag character (ASCII smuggling)",
        "finding.variation_selector": "Variation selector (payload carrier)",
        "finding.emoji_selector": "Emoji presentation selector (normal)",
        "finding.pua": "Private Use Area character",
        "finding.invisible_format": "Invisible formatting character",
        "finding.control": "Control character",
        "finding.invisible_run": "Run of invisible characters",
        "finding.hidden_string": "Decoded hidden string",
        "finding.author_mark": "Author mark detected",
        "finding.homoglyph": "Mixed scripts (homoglyph spoofing)",
        "finding.encoded_string": "Encoded string",
        "finding.watermark_dunder": "Watermark in code",
        "finding.watermark_comment": "Mark in a comment",
        "finding.sensitive_import": "Sensitive library import",
        "finding.network_call": "Network access",
        "finding.network_calls": "Network calls (normal for networked apps)",
        "finding.shell_exec": "System command execution",
        "finding.shell_execs": "System command execution",
        "finding.exec_decoded": "exec/eval with decoding — obfuscation!",
        "finding.exec_dynamic": "exec/eval with a dynamic argument",
        "finding.exec_literal": "exec/eval/compile call",
        "finding.parse_error": "Could not parse syntax (AST skipped)",
        "finding.detector_error": "Detector failure",
        # --- secrets ---
        "secret.aws_key": "AWS access key",
        "secret.telegram_token": "Telegram bot token",
        "secret.stripe_live": "Stripe live key",
        "secret.github_token": "GitHub token",
        "secret.github_pat": "GitHub personal token",
        "secret.google_api": "Google API key",
        "secret.slack_token": "Slack token",
        "secret.private_key": "Private key",
        "secret.jwt": "JWT token",
        "secret.generic": "Looks like a secret in code",
        # --- recommendations ---
        "rec.invisible": "Invisible characters in source are an anomaly. Inspect "
                         "the run and clean the file if needed.",
        "rec.emoji": "Emoji selector — part of an emoji glyph, usually harmless.",
        "rec.hidden_string": "A hidden message is embedded in the code. Review its "
                             "content before running the file.",
        "rec.foreign_mark": "This mark is not yours. Verify where the file came "
                            "from.",
        "rec.homoglyph": "Letters from different scripts in one word are a common "
                         "disguise. Compare with the original.",
        "rec.secret": "Remove the secret from code before publishing and rotate it.",
        "rec.encoded_string": "Check what the encoded string hides.",
        "rec.sensitive_import": "Make sure the library is used legitimately.",
        "rec.network_call": "Verify where and why the code reaches the network.",
        "rec.shell_exec": "Running shell commands is risky — verify the source.",
        "rec.dangerous_exec": "Dynamic code execution is a classic malware trick. "
                              "Review it by hand.",
        "rec.parse_error": "File does not parse as Python. Only text and invisible "
                           "characters were checked.",
    },
}


class Translator:
    """Простой переводчик с переключаемым языком."""

    def __init__(self, lang: str = "ru") -> None:
        self.lang = lang if lang in LANGUAGES else "ru"

    def set_language(self, lang: str) -> None:
        if lang in LANGUAGES:
            self.lang = lang

    def tr(self, key: str, **fmt: object) -> str:
        """Возвращает перевод по ключу. Отсутствующий ключ → сам ключ."""
        template = STRINGS.get(self.lang, {}).get(key)
        if template is None:
            template = STRINGS["ru"].get(key, key)
        if fmt:
            try:
                return template.format(**fmt)
            except (KeyError, IndexError, ValueError):
                return template
        return template
