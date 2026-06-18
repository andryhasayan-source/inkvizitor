"""
Инквизитор — графический интерфейс (PyQt6).
ShashevPro · https://www.shashevpro.ru/

Тёмная техно-минималистичная тема, перетаскивание файлов/папок, светофор
статусов, сворачиваемые карточки файлов, переключение языка на лету и
кликабельный копирайт ShashevPro. Сканирование идёт в отдельном потоке —
интерфейс не подвисает.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from engine import (
    FileReport,
    Finding,
    Scanner,
    ScanReport,
    clean_text,
    read_source,
)
from i18n import STRINGS, Translator
from reporting import SITE_URL, build_html_report, build_text_report

ASSETS = Path(__file__).resolve().parent / "assets"

SEV_COLOR = {
    "critical": "#f85149",
    "high": "#ff7b54",
    "medium": "#d29922",
    "low": "#58a6ff",
    "info": "#8b949e",
}
STATUS_COLOR = {"green": "#3fb950", "yellow": "#d29922", "red": "#f85149"}


def _esc(text: str) -> str:
    return html.escape(text)


# Тёмная тема приложения (QSS)
QSS = """
QWidget {
    background: #0d1117; color: #e6edf3;
    font-family: "JetBrains Mono", "Cascadia Code", Consolas, monospace;
    font-size: 13px;
}
#Header { background: #12101a; border-bottom: 1px solid #30363d; }
#AppTitle { font-size: 20px; font-weight: 700; }
#Tagline { color: #8b949e; font-size: 12px; }
QPushButton {
    background: #21262d; border: 1px solid #30363d; border-radius: 8px;
    padding: 8px 14px; color: #e6edf3;
}
QPushButton:hover { background: #2d333b; border-color: #444c56; }
QPushButton:pressed { background: #1c2128; }
#ScanButton {
    background: #b62324; border: 1px solid #f85149; border-radius: 10px;
    padding: 12px 22px; font-size: 15px; font-weight: 700; color: #ffffff;
}
#ScanButton:hover { background: #d12d2e; }
#ScanButton:disabled { background: #3a2222; color: #9b8585; border-color: #5a3030; }
#LangButton { padding: 5px 10px; min-width: 38px; }
#LangButton:checked {
    background: #b62324; border-color: #f85149; color: #ffffff;
}
#DropArea {
    border: 2px dashed #30363d; border-radius: 14px; background: #131922;
}
#DropArea[active="true"] { border-color: #f85149; background: #1a1416; }
#DropHint { color: #8b949e; font-size: 14px; }
#StatCard { background: #161b22; border: 1px solid #30363d; border-radius: 12px; }
#StatNum { font-size: 26px; font-weight: 700; }
#StatLbl { color: #8b949e; font-size: 11px; }
#FileCard { background: #161b22; border: 1px solid #30363d; border-radius: 10px; }
#FileHeader { background: transparent; border: none; text-align: left; padding: 0; }
#FilePath { font-size: 13px; }
#FileMeta { color: #8b949e; font-size: 11px; }
#FindingTitle { font-weight: 600; }
#FindingDetail {
    background: #1c2330; border-radius: 8px; padding: 7px 9px;
    color: #c9d1d9; font-size: 12px;
}
#FindingRec { color: #8b949e; font-size: 11px; }
#Badge { border-radius: 6px; padding: 2px 7px; font-size: 10px; font-weight: 700; }
#OkLabel { color: #3fb950; padding: 10px 14px; }
#Footer { color: #8b949e; font-size: 11px; }
#FooterLink { color: #ff7b54; background: transparent; border: none; padding: 0; }
#FooterLink:hover { text-decoration: underline; }
QProgressBar {
    border: 1px solid #30363d; border-radius: 7px; background: #161b22;
    text-align: center; height: 16px; color: #e6edf3;
}
QProgressBar::chunk { background: #b62324; border-radius: 6px; }
QScrollArea { border: none; }
QScrollBar:vertical { background: #0d1117; width: 11px; margin: 0; }
QScrollBar::handle:vertical { background: #30363d; border-radius: 5px; min-height: 28px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""


class ScanWorker(QThread):
    """Фоновый поток сканирования, чтобы интерфейс не подвисал."""

    progress = pyqtSignal(int, int, str)
    done = pyqtSignal(object)

    def __init__(self, target: str, workers: int = 4) -> None:
        super().__init__()
        self.target = target
        self.workers = workers

    def run(self) -> None:
        scanner = Scanner(max_workers=self.workers)
        report = scanner.scan(
            self.target,
            progress=lambda d, t, p: self.progress.emit(d, t, p),
        )
        self.done.emit(report)


class StatCard(QFrame):
    """Карточка одной цифры в сводке."""

    def __init__(self, accent: str | None = None) -> None:
        super().__init__()
        self.setObjectName("StatCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        self.num = QLabel("0")
        self.num.setObjectName("StatNum")
        if accent:
            self.num.setStyleSheet(f"color: {accent};")
        self.lbl = QLabel("")
        self.lbl.setObjectName("StatLbl")
        layout.addWidget(self.num)
        layout.addWidget(self.lbl)

    def set_value(self, value: int, label: str) -> None:
        self.num.setText(str(value))
        self.lbl.setText(label)


class FindingRow(QWidget):
    """Строка одной находки: бейдж опасности + заголовок + детали."""

    def __init__(self, finding: Finding, t: Translator) -> None:
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 10)
        layout.setSpacing(10)
        self.setStyleSheet("border-top: 1px solid #30363d;")

        color = SEV_COLOR.get(finding.severity, "#8b949e")
        badge = QLabel(t.tr(f"sev.{finding.severity}"))
        badge.setObjectName("Badge")
        badge.setStyleSheet(f"#Badge {{ color: {color}; border: 1px solid {color}; }}")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedWidth(118)

        right = QVBoxLayout()
        right.setSpacing(4)
        loc = ""
        if finding.line is not None:
            loc = f"  · {finding.line}"
            if finding.column:
                loc += f":{finding.column}"
        title = QLabel(
            f'{_esc(t.tr(finding.title_key))}'
            f'<span style="color:#8b949e">{_esc(loc)}</span>'
        )
        title.setObjectName("FindingTitle")
        title.setTextFormat(Qt.TextFormat.RichText)
        title.setWordWrap(True)
        right.addWidget(title)

        if finding.detail:
            detail = QLabel(finding.detail)
            detail.setObjectName("FindingDetail")
            detail.setWordWrap(True)
            detail.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            right.addWidget(detail)
        if finding.rec_key:
            rec = QLabel("⚑ " + t.tr(finding.rec_key))
            rec.setObjectName("FindingRec")
            rec.setWordWrap(True)
            right.addWidget(rec)

        layout.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(right, 1)


class FileCard(QFrame):
    """Сворачиваемая карточка одного файла с находками."""

    def __init__(self, report: FileReport, t: Translator) -> None:
        super().__init__()
        self.setObjectName("FileCard")
        self.report = report
        self.setStyleSheet(
            f"#FileCard {{ border-left: 5px solid {STATUS_COLOR[report.status]}; }}"
        )

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.header = QPushButton()
        self.header.setObjectName("FileHeader")
        self.header.setCursor(Qt.CursorShape.PointingHandCursor)
        row = QHBoxLayout(self.header)
        row.setContentsMargins(12, 10, 14, 10)
        self.arrow = QLabel("▸")
        self.arrow.setStyleSheet("color: #8b949e;")
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {STATUS_COLOR[report.status]}; font-size: 14px;")
        path = QLabel(report.path)
        path.setObjectName("FilePath")
        path.setWordWrap(True)
        n = len(report.findings)
        meta_text = t.tr("ui.encoding") + f": {report.encoding}"
        if n:
            meta_text = f"{n} · " + meta_text
        meta = QLabel(meta_text)
        meta.setObjectName("FileMeta")
        row.addWidget(self.arrow)
        row.addWidget(dot)
        row.addWidget(path, 1)
        row.addWidget(meta)
        self.header.clicked.connect(self._toggle)
        outer.addWidget(self.header)

        self.body = QWidget()
        body_layout = QVBoxLayout(self.body)
        body_layout.setContentsMargins(14, 0, 14, 12)
        body_layout.setSpacing(0)
        if report.findings:
            for finding in report.findings:
                body_layout.addWidget(FindingRow(finding, t))
        else:
            ok = QLabel(f"✅ {t.tr('ui.no_findings')}")
            ok.setObjectName("OkLabel")
            body_layout.addWidget(ok)
        outer.addWidget(self.body)

        # файлы с находками раскрыты сразу, чистые — свёрнуты
        self.body.setVisible(bool(report.findings))
        self._update_arrow()

    def _toggle(self) -> None:
        self.body.setVisible(not self.body.isVisible())
        self._update_arrow()

    def _update_arrow(self) -> None:
        self.arrow.setText("▾" if self.body.isVisible() else "▸")

    def set_expanded(self, expanded: bool) -> None:
        self.body.setVisible(expanded)
        self._update_arrow()


class CleanSummaryCard(QFrame):
    """Свёрнутая сводка по чистым файлам — одна строка вместо десятков карточек.

    По клику разворачивается в список путей, чтобы можно было убедиться,
    что нужный файл проверен и в нём ничего не найдено.
    """

    def __init__(self, reports: list[FileReport], t: Translator) -> None:
        super().__init__()
        self.setObjectName("FileCard")
        self.setStyleSheet("#FileCard { border-left: 5px solid #3fb950; }")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.header = QPushButton()
        self.header.setObjectName("FileHeader")
        self.header.setCursor(Qt.CursorShape.PointingHandCursor)
        row = QHBoxLayout(self.header)
        row.setContentsMargins(12, 10, 14, 10)
        self.arrow = QLabel("▸")
        self.arrow.setStyleSheet("color: #8b949e;")
        dot = QLabel("✅")
        title = QLabel(t.tr("ui.clean_summary", count=len(reports)))
        title.setObjectName("FilePath")
        title.setWordWrap(True)
        row.addWidget(self.arrow)
        row.addWidget(dot)
        row.addWidget(title, 1)
        self.header.clicked.connect(self._toggle)
        outer.addWidget(self.header)

        self.body = QWidget()
        body_layout = QVBoxLayout(self.body)
        body_layout.setContentsMargins(38, 0, 14, 12)
        body_layout.setSpacing(2)
        for fr in reports:
            lbl = QLabel(fr.path)
            lbl.setObjectName("FileMeta")
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            body_layout.addWidget(lbl)
        outer.addWidget(self.body)
        self.body.setVisible(False)

    def _toggle(self) -> None:
        self.body.setVisible(not self.body.isVisible())
        self.arrow.setText("▾" if self.body.isVisible() else "▸")


class DropArea(QFrame):
    """Зона перетаскивания файла или папки."""

    def __init__(self, on_path) -> None:
        super().__init__()
        self.setObjectName("DropArea")
        self.on_path = on_path
        self.setAcceptDrops(True)
        self.setMinimumHeight(110)
        layout = QVBoxLayout(self)
        self.hint = QLabel("")
        self.hint.setObjectName("DropHint")
        self.hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)

    def set_hint(self, text: str) -> None:
        self.hint.setText(text)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setProperty("active", "true")
            self._restyle()

    def dragLeaveEvent(self, event) -> None:
        self.setProperty("active", "false")
        self._restyle()

    def dropEvent(self, event) -> None:
        self.setProperty("active", "false")
        self._restyle()
        urls = event.mimeData().urls()
        if urls:
            self.on_path(urls[0].toLocalFile())

    def _restyle(self) -> None:
        self.style().unpolish(self)
        self.style().polish(self)


class MainWindow(QWidget):
    """Главное окно Инквизитора."""

    def __init__(self, lang: str = "ru") -> None:
        super().__init__()
        self.t = Translator(lang)
        self.target: str | None = None
        self.report: ScanReport | None = None
        self.worker: ScanWorker | None = None
        self._file_cards: list[FileCard] = []

        self.setWindowTitle(f"{self.t.tr('app.name')} — ShashevPro")
        self.resize(900, 720)
        icon = self._load_icon()
        if icon is not None:
            self.setWindowIcon(icon)
        self.setStyleSheet(QSS)
        self._build_ui()
        self.retranslate()
        self._lock_button_widths()

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _load_icon() -> QIcon | None:
        for name in ("icon.ico", "icon.png"):
            path = ASSETS / name
            if path.exists():
                return QIcon(str(path))
        return None

    # ----------------------------------------------------------------- UI

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_header())

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(22, 18, 22, 12)
        layout.setSpacing(14)

        self.drop = DropArea(self._set_target)
        layout.addWidget(self.drop)

        controls = QHBoxLayout()
        self.btn_file = QPushButton()
        self.btn_file.clicked.connect(self._pick_file)
        self.btn_folder = QPushButton()
        self.btn_folder.clicked.connect(self._pick_folder)
        self.btn_scan = QPushButton()
        self.btn_scan.setObjectName("ScanButton")
        self.btn_scan.clicked.connect(self._start_scan)
        controls.addWidget(self.btn_file)
        controls.addWidget(self.btn_folder)
        controls.addStretch(1)
        controls.addWidget(self.btn_scan)
        layout.addLayout(controls)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.status_label = QLabel()
        self.status_label.setObjectName("Tagline")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.summary = QHBoxLayout()
        self.summary.setSpacing(12)
        self.card_files = StatCard()
        self.card_threats = StatCard(accent="#f85149")
        self.card_marks = StatCard(accent="#d2a8ff")
        self.card_issues = StatCard()
        self._stat_cards = (
            self.card_files, self.card_threats, self.card_marks, self.card_issues
        )
        for card in self._stat_cards:
            self.summary.addWidget(card)
        layout.addLayout(self.summary)
        self._set_summary_visible(False)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.results_holder = QWidget()
        self.results_layout = QVBoxLayout(self.results_holder)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(10)
        self.results_layout.addStretch(1)
        scroll.setWidget(self.results_holder)
        layout.addWidget(scroll, 1)

        layout.addLayout(self._build_toolbar())
        root.addWidget(content, 1)
        root.addWidget(self._build_footer())

    def _build_header(self) -> QWidget:
        header = QFrame()
        header.setObjectName("Header")
        row = QHBoxLayout(header)
        row.setContentsMargins(22, 14, 18, 14)

        icon = self._load_icon()
        if icon is not None:
            logo = QLabel()
            logo.setPixmap(icon.pixmap(34, 34))
            row.addWidget(logo)

        titles = QVBoxLayout()
        titles.setSpacing(0)
        self.title_label = QLabel()
        self.title_label.setObjectName("AppTitle")
        self.title_label.setTextFormat(Qt.TextFormat.RichText)
        self.tagline_label = QLabel()
        self.tagline_label.setObjectName("Tagline")
        titles.addWidget(self.title_label)
        titles.addWidget(self.tagline_label)
        row.addLayout(titles)
        row.addStretch(1)

        self.lang_buttons: dict[str, QPushButton] = {}
        for code, label in (("ru", "RU"), ("en", "EN")):
            btn = QPushButton(label)
            btn.setObjectName("LangButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _checked, c=code: self._set_language(c))
            self.lang_buttons[code] = btn
            row.addWidget(btn)
        self.lang_buttons[self.t.lang].setChecked(True)
        return header

    def _build_toolbar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        self.btn_save = QPushButton()
        self.btn_save.clicked.connect(self._save_report)
        self.btn_clean = QPushButton()
        self.btn_clean.clicked.connect(self._clean_file)
        self.btn_reset = QPushButton()
        self.btn_reset.clicked.connect(self._reset)
        for btn in (self.btn_save, self.btn_clean):
            btn.setEnabled(False)
        bar.addWidget(self.btn_save)
        bar.addWidget(self.btn_clean)
        bar.addStretch(1)
        bar.addWidget(self.btn_reset)
        return bar

    def _build_footer(self) -> QWidget:
        footer = QFrame()
        footer.setObjectName("Footer")
        row = QHBoxLayout(footer)
        row.setContentsMargins(22, 8, 22, 10)
        self.footer_link = QPushButton()
        self.footer_link.setObjectName("FooterLink")
        self.footer_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self.footer_link.setFlat(True)
        self.footer_link.clicked.connect(self._open_site)
        row.addStretch(1)
        row.addWidget(self.footer_link)
        row.addStretch(1)
        return footer

    # ------------------------------------------------------------- i18n

    def retranslate(self) -> None:
        """Обновляет все видимые тексты под текущий язык."""
        self.title_label.setText(
            f'{_esc(self.t.tr("app.name"))} '
            f'<span style="color:#f85149">·</span>'
        )
        self.tagline_label.setText(self.t.tr("app.tagline"))
        self.drop.set_hint(self.t.tr("ui.drop_hint"))
        self.btn_file.setText(self.t.tr("ui.choose_file"))
        self.btn_folder.setText(self.t.tr("ui.choose_folder"))
        self.btn_scan.setText(self.t.tr("ui.scan"))
        self.btn_save.setText(self.t.tr("ui.save_report"))
        self.btn_clean.setText(self.t.tr("ui.clean_file"))
        self.btn_reset.setText(self.t.tr("ui.reset"))
        self.footer_link.setText(self.t.tr("ui.copyright", year=datetime.now().year))
        if self.report is None:
            self.status_label.setText(
                self.target if self.target else self.t.tr("ui.idle")
            )
        else:
            self._render_results()

    def _set_language(self, code: str) -> None:
        self.t.set_language(code)
        for c, btn in self.lang_buttons.items():
            btn.setChecked(c == code)
        self.retranslate()

    def _lock_button_widths(self) -> None:
        """Фиксирует ширину кнопок по самому широкому языку.

        Иначе при переключении RU → EN короткие английские подписи ужимают
        кнопки и верстка прыгает. Меряем ширину под оба языка и берём максимум.
        """
        specs = (
            (self.btn_file, "ui.choose_file"),
            (self.btn_folder, "ui.choose_folder"),
            (self.btn_scan, "ui.scan"),
            (self.btn_save, "ui.save_report"),
            (self.btn_clean, "ui.clean_file"),
            (self.btn_reset, "ui.reset"),
        )
        for button, key in specs:
            button.ensurePolished()
            width = 0
            for lang in ("ru", "en"):
                button.setText(STRINGS[lang].get(key, key))
                width = max(width, button.sizeHint().width())
            button.setText(self.t.tr(key))
            button.setFixedWidth(width)

    # --------------------------------------------------------- targets

    def _set_target(self, path: str) -> None:
        if not path:
            return
        self.target = path
        self.status_label.setText(path)

    def _pick_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, self.t.tr("ui.choose_file"), "", "Python (*.py *.pyw);;All (*)"
        )
        if path:
            self._set_target(path)

    def _pick_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, self.t.tr("ui.choose_folder"))
        if path:
            self._set_target(path)

    # --------------------------------------------------------- scanning

    def _start_scan(self) -> None:
        if not self.target:
            QMessageBox.information(
                self, self.t.tr("app.name"), self.t.tr("msg.pick_first")
            )
            return
        self.btn_scan.setEnabled(False)
        self.btn_save.setEnabled(False)
        self.btn_clean.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.status_label.setText(self.t.tr("ui.scanning"))

        self.worker = ScanWorker(self.target)
        self.worker.progress.connect(self._on_progress)
        self.worker.done.connect(self._on_done)
        self.worker.start()

    def _on_progress(self, done: int, total: int, path: str) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(done)

    def _on_done(self, report: ScanReport) -> None:
        self.report = report
        self.progress.setVisible(False)
        self.btn_scan.setEnabled(True)
        self.btn_save.setEnabled(report.files_scanned > 0)
        self.btn_clean.setEnabled(self._is_single_file())
        if report.files_scanned == 0:
            QMessageBox.information(
                self, self.t.tr("app.name"), self.t.tr("msg.no_py_files")
            )
        self._render_results()

    def _is_single_file(self) -> bool:
        return bool(self.target) and Path(self.target).is_file()

    # ------------------------------------------------------- rendering

    def _set_summary_visible(self, visible: bool) -> None:
        for card in getattr(self, "_stat_cards", ()):
            card.setVisible(visible)

    def _render_results(self) -> None:
        if self.report is None:
            return
        r = self.report
        self._set_summary_visible(True)
        self.card_files.set_value(r.files_scanned, self.t.tr("ui.files_scanned"))
        self.card_threats.set_value(r.threats, self.t.tr("ui.threats"))
        self.card_marks.set_value(r.author_marks, self.t.tr("ui.marks"))
        self.card_issues.set_value(r.files_with_issues, self.t.tr("ui.issues"))

        # очищаем прошлый список
        while self.results_layout.count() > 1:
            item = self.results_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._file_cards = []

        flagged = [fr for fr in r.file_reports if fr.findings]
        clean = [fr for fr in r.file_reports if not fr.findings]

        def add(widget: QWidget) -> None:
            self.results_layout.insertWidget(self.results_layout.count() - 1, widget)

        if not flagged and clean:
            # ничего не найдено — сразу показываем вердикт, без открывания
            if len(clean) == 1:
                add(self._clean_file_banner(clean[0]))
            else:
                add(self._all_clean_banner(len(clean)))
        else:
            for fr in flagged:
                card = FileCard(fr, self.t)  # с находками — раскрыт сразу
                self._file_cards.append(card)
                add(card)
            if clean:
                add(CleanSummaryCard(clean, self.t))

        elapsed = ""
        if r.finished_at:
            secs = (r.finished_at - r.started_at).total_seconds()
            elapsed = f"  ·  {secs:.2f} s"
        self.status_label.setText(self.target + elapsed if self.target else "")

    def _all_clean_banner(self, count: int) -> QWidget:
        banner = QFrame()
        banner.setObjectName("FileCard")
        banner.setStyleSheet("#FileCard { border-left: 5px solid #3fb950; }")
        layout = QVBoxLayout(banner)
        layout.setContentsMargins(16, 16, 16, 16)
        label = QLabel("✅ " + self.t.tr("ui.all_clean", count=count))
        label.setObjectName("OkLabel")
        label.setWordWrap(True)
        layout.addWidget(label)
        return banner

    def _clean_file_banner(self, fr: FileReport) -> QWidget:
        """Зелёная плашка для одиночного чистого файла — вердикт виден сразу."""
        banner = QFrame()
        banner.setObjectName("FileCard")
        banner.setStyleSheet("#FileCard { border-left: 5px solid #3fb950; }")
        layout = QVBoxLayout(banner)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)
        msg = QLabel("✅ " + self.t.tr("ui.no_findings"))
        msg.setStyleSheet("color: #3fb950; font-size: 14px; font-weight: 600;")
        msg.setWordWrap(True)
        meta = QLabel(f"{fr.path}   ·   {self.t.tr('ui.encoding')}: {fr.encoding}")
        meta.setObjectName("FileMeta")
        meta.setWordWrap(True)
        meta.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(msg)
        layout.addWidget(meta)
        return banner

    # --------------------------------------------------------- actions

    def _save_report(self) -> None:
        if self.report is None:
            return
        path, selected = QFileDialog.getSaveFileName(
            self,
            self.t.tr("ui.save_report"),
            f"inkvizitor_report_{datetime.now():%Y%m%d_%H%M}.html",
            "HTML (*.html);;Text (*.txt)",
        )
        if not path:
            return
        is_html = path.lower().endswith(".html") or "HTML" in selected
        if is_html:
            content = build_html_report(self.report, self.t.lang)
            if not path.lower().endswith(".html"):
                path += ".html"
        else:
            content = build_text_report(self.report, self.t.lang)
            if not path.lower().endswith(".txt"):
                path += ".txt"
        try:
            Path(path).write_text(content, encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, self.t.tr("app.name"), str(exc))
            return
        QMessageBox.information(
            self, self.t.tr("app.name"), self.t.tr("msg.report_saved", path=path)
        )

    def _clean_file(self) -> None:
        if not self._is_single_file():
            QMessageBox.information(
                self, self.t.tr("app.name"), self.t.tr("msg.clean_one_file")
            )
            return
        src = Path(self.target)  # type: ignore[arg-type]
        text, _enc, _err = read_source(src)
        if text is None:
            return
        cleaned, removed = clean_text(text)
        if removed == 0:
            QMessageBox.information(
                self, self.t.tr("app.name"), self.t.tr("msg.clean_nothing")
            )
            return
        default = str(src.with_name(src.stem + ".cleaned" + src.suffix))
        path, _ = QFileDialog.getSaveFileName(
            self, self.t.tr("ui.clean_file"), default, "Python (*.py *.pyw);;All (*)"
        )
        if not path:
            return
        try:
            Path(path).write_text(cleaned, encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, self.t.tr("app.name"), str(exc))
            return
        QMessageBox.information(
            self,
            self.t.tr("app.name"),
            self.t.tr("msg.cleaned", count=removed, path=path),
        )

    def _reset(self) -> None:
        """Очищает прошлую проверку и путь — программа снова чистая, как после запуска."""
        self.target = None
        self.report = None
        self.status_label.setText(self.t.tr("ui.idle"))
        self.progress.setVisible(False)
        self.progress.setValue(0)
        self.btn_save.setEnabled(False)
        self.btn_clean.setEnabled(False)
        self._set_summary_visible(False)
        while self.results_layout.count() > 1:
            item = self.results_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._file_cards = []

    def _open_site(self) -> None:
        QDesktopServices.openUrl(QUrl(SITE_URL))


def run_gui(lang: str = "ru") -> int:
    """Запускает приложение. Возвращает код выхода."""
    import sys

    app = QApplication.instance() or QApplication(sys.argv)
    window = MainWindow(lang=lang)
    window.show()
    return app.exec()
