"""
Инквизитор — точка входа.
ShashevPro · https://www.shashevpro.ru/

Без аргументов запускается графический интерфейс. Если передан путь —
работает консольный режим с цветным выводом (offline, без сети):

    python main.py                      → графический интерфейс
    python main.py path/to/project      → консольная проверка
    python main.py file.py --lang en    → проверка на английском
    python main.py src --save out.txt   → сохранить текстовый отчёт
    python main.py src --html out.html  → сохранить HTML-отчёт
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from engine import Finding, Scanner
from i18n import Translator
from reporting import build_html_report, build_text_report

# colorama — опционально; без неё вывод просто без цвета
try:
    from colorama import Fore, Style
    from colorama import init as _color_init

    _color_init()
    _HAS_COLOR = True
except ImportError:  # pragma: no cover
    _HAS_COLOR = False

    class _Dummy:
        def __getattr__(self, _name: str) -> str:
            return ""

    Fore = Style = _Dummy()  # type: ignore[assignment]

_SEV_COLOR = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "info": Fore.WHITE,
}
_STATUS_COLOR = {
    "green": Fore.GREEN,
    "yellow": Fore.YELLOW,
    "red": Fore.RED + Style.BRIGHT,
}


def _c(text: str, color: str) -> str:
    """Окрашивает текст, если доступна colorama."""
    return f"{color}{text}{Style.RESET_ALL}" if _HAS_COLOR else text


def print_cli(report, lang: str) -> None:
    """Печатает цветной отчёт в консоль."""
    t = Translator(lang)
    bar = "=" * 60
    print(_c(bar, Fore.RED))
    print(_c(f"  {t.tr('app.name').upper()} — {t.tr('app.tagline')}", Style.BRIGHT))
    print("  ShashevPro · https://www.shashevpro.ru/")
    print(_c(bar, Fore.RED))

    for fr in report.file_reports:
        print()
        print(_c(f"● {fr.path}  ({t.tr('ui.encoding')}: {fr.encoding})",
                 _STATUS_COLOR[fr.status]))
        if not fr.findings:
            print(_c(f"    ✓ {t.tr('ui.no_findings')}", Fore.GREEN))
            continue
        for f in fr.findings:
            sev = t.tr(f"sev.{f.severity}")
            loc = ""
            if f.line is not None:
                loc = f"  ({f.line}" + (f":{f.column}" if f.column else "") + ")"
            head = f"    [{sev}] {t.tr(f.title_key)}{loc}"
            print(_c(head, _SEV_COLOR.get(f.severity, "")))
            if f.detail:
                print(f"        -> {f.detail}")

    print()
    print(_c(bar, Fore.RED))
    print(f"  {t.tr('ui.files_scanned')}: {report.files_scanned}")
    print(_c(f"  {t.tr('ui.threats')}: {report.threats}",
             Fore.RED if report.threats else ""))
    print(f"  {t.tr('ui.marks')}: {report.author_marks}")
    print(_c(bar, Fore.RED))


def run_cli(args: argparse.Namespace) -> int:
    """Консольный режим сканирования."""
    target = Path(args.path)
    if not target.exists():
        print(f"Путь не найден: {target}", file=sys.stderr)
        return 2

    report = Scanner().scan(str(target))
    print_cli(report, args.lang)

    if args.save:
        Path(args.save).write_text(
            build_text_report(report, args.lang), encoding="utf-8"
        )
        print(f"\n{Translator(args.lang).tr('msg.report_saved', path=args.save)}")
    if args.html:
        Path(args.html).write_text(
            build_html_report(report, args.lang), encoding="utf-8"
        )
        print(f"{Translator(args.lang).tr('msg.report_saved', path=args.html)}")
    return 1 if report.threats else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="inkvizitor",
        description="Инквизитор — сканер скрытых меток в Python-коде (ShashevPro).",
    )
    parser.add_argument("path", nargs="?", help="файл .py или папка проекта")
    parser.add_argument("--lang", choices=("ru", "en"), default="ru")
    parser.add_argument("--save", metavar="FILE", help="сохранить текстовый отчёт")
    parser.add_argument("--html", metavar="FILE", help="сохранить HTML-отчёт")
    args = parser.parse_args()

    if args.path:
        return run_cli(args)

    # Графический режим
    try:
        from gui import run_gui
    except ImportError as exc:
        print(
            "Не удалось запустить графический интерфейс "
            f"(нужен PyQt6): {exc}\n"
            "Установите: pip install PyQt6\n"
            "Либо используйте консольный режим: python main.py <путь>",
            file=sys.stderr,
        )
        return 3
    return run_gui(args.lang)


if __name__ == "__main__":
    raise SystemExit(main())
