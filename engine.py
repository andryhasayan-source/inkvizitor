"""
Инквизитор — движок сканирования скрытых меток в Python-коде.
ShashevPro · https://www.shashevpro.ru/

Движок не зависит от сторонних библиотек (только стандартная библиотека).
Опционально используются:
  - charset-normalizer  — для определения кодировки нестандартных файлов;
  - zwsp-steg-py         — как дополнительный путь декодирования стеганографии.
Оба импортируются мягко: при их отсутствии движок продолжает работать.

Архитектура: набор независимых детекторов, каждый возвращает список Finding.
Scanner обходит файлы потоково (по одному), что бережёт память на больших
проектах, и распараллеливает работу через ThreadPoolExecutor.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from math import log2
from pathlib import Path
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# Константы степени опасности
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Формат метки автора ShashevPro
MARK_MAGIC = "SHASH"
MARK_DOMAIN = "shashevpro.ru"

# Канонический алфавит для метки ShashevPro (схема V2 — 8 символов, 3 бита/символ)
V2_ALPHABET = [
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\u2062",  # invisible times
    "\u2063",  # invisible separator
    "\u2064",  # invisible plus
    "\ufeff",  # zero-width no-break space / BOM
]


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """Одна находка детектора.

    Attributes:
        kind: Категория (zero_width, author_mark, secret, suspicious_code, ...).
        severity: info / low / medium / high / critical.
        title_key: Ключ для перевода краткого заголовка.
        line: Номер строки (если применимо).
        column: Номер столбца (если применимо).
        detail: Языконезависимые подробности (декодированный текст, сниппет).
        rec_key: Ключ перевода рекомендации.
        extra: Структурированные данные (кодпойнт, имя символа, поля метки).
    """

    kind: str
    severity: str
    title_key: str
    line: int | None = None
    column: int | None = None
    detail: str = ""
    rec_key: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class FileReport:
    """Результат сканирования одного файла."""

    path: str
    encoding: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    @property
    def status(self) -> str:
        """Цвет светофора: green / yellow / red."""
        rank = SEVERITY_ORDER[self.max_severity] if self.findings else -1
        if rank >= SEVERITY_ORDER["high"]:
            return "red"
        if rank >= SEVERITY_ORDER["low"]:
            return "yellow"
        return "green"

    @property
    def threats(self) -> int:
        """Серьёзные угрозы (high + critical)."""
        return sum(
            1
            for f in self.findings
            if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["high"]
        )

    @property
    def author_marks(self) -> int:
        return sum(1 for f in self.findings if f.kind == "author_mark")


@dataclass
class ScanReport:
    """Сводный отчёт по всем файлам."""

    file_reports: list[FileReport] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None

    @property
    def files_scanned(self) -> int:
        return len(self.file_reports)

    @property
    def threats(self) -> int:
        return sum(fr.threats for fr in self.file_reports)

    @property
    def author_marks(self) -> int:
        return sum(fr.author_marks for fr in self.file_reports)

    @property
    def files_with_issues(self) -> int:
        return sum(1 for fr in self.file_reports if fr.findings)

    @property
    def total_findings(self) -> int:
        return sum(len(fr.findings) for fr in self.file_reports)


# ---------------------------------------------------------------------------
# Классификация подозрительных символов Юникода
# ---------------------------------------------------------------------------

# Невидимые символы нулевой ширины и невидимые операторы
_ZERO_WIDTH: frozenset[int] = frozenset(
    {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF}
)

# Управление направлением текста (атака Trojan Source)
_BIDI: frozenset[int] = frozenset(
    {0x200E, 0x200F, 0x061C}
    | set(range(0x202A, 0x202F))
    | set(range(0x2066, 0x206A))
)

# Прочие невидимые / форматирующие символы
_OTHER_INVISIBLE: frozenset[int] = frozenset(
    {
        0x00AD,  # soft hyphen
        0x034F,  # combining grapheme joiner
        0x115F,  # hangul choseong filler
        0x1160,  # hangul jungseong filler
        0x17B4,  # khmer vowel inherent aq
        0x17B5,  # khmer vowel inherent aa
        0x180E,  # mongolian vowel separator
        0x2028,  # line separator
        0x2029,  # paragraph separator
        0x3164,  # hangul filler
        0xFFA0,  # halfwidth hangul filler
    }
)

# Управляющие символы C0/C1, кроме обычных tab / newline / carriage return
_CONTROL: frozenset[int] = frozenset(
    set(range(0x00, 0x09))
    | {0x0B, 0x0C}
    | set(range(0x0E, 0x20))
    | set(range(0x7F, 0xA0))
)

# Символы, пригодные для переноса стеганографического payload
_STEGO_CAPABLE: frozenset[int] = _ZERO_WIDTH | frozenset(
    set(range(0xFE00, 0xFE10))  # variation selectors
    | set(range(0xE0100, 0xE01F0))  # variation selectors supplement
    | set(range(0xE0000, 0xE0080))  # tag characters
)


def classify_char(cp: int) -> tuple[str, str] | None:
    """Классифицирует кодпойнт. Возвращает (категория, опасность) или None.

    None означает, что символ нормальный и не вызывает подозрений.
    """
    if cp in _ZERO_WIDTH:
        return ("zero_width", "medium")
    if cp in _BIDI:
        return ("bidi", "high")
    if 0xE0000 <= cp <= 0xE007F:
        return ("tag", "critical")
    if cp in (0xFE0E, 0xFE0F):
        return ("emoji_selector", "info")
    if 0xFE00 <= cp <= 0xFE0D:
        return ("variation_selector", "low")
    if 0xE0100 <= cp <= 0xE01EF:
        return ("variation_selector", "high")
    if (0xE000 <= cp <= 0xF8FF) or (0xF0000 <= cp <= 0xFFFFD) or (
        0x100000 <= cp <= 0x10FFFD
    ):
        return ("pua", "high")
    if cp in _OTHER_INVISIBLE:
        return ("invisible_format", "medium")
    if cp in _CONTROL:
        return ("control", "medium")
    return None


def char_name(cp: int) -> str:
    """Возвращает имя символа Юникода (U+XXXX NAME)."""
    import unicodedata

    try:
        name = unicodedata.name(chr(cp))
    except (ValueError, TypeError):
        name = "UNNAMED"
    return f"U+{cp:04X} {name}"


# ---------------------------------------------------------------------------
# Стеганография: декодирование и кодирование меток
# ---------------------------------------------------------------------------


def _bits_to_bytes(bits: str) -> bytes:
    """Группирует битовую строку по 8, отбрасывая неполный хвост."""
    usable = len(bits) - (len(bits) % 8)
    bits = bits[:usable]
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def _decode_power_of_two(carrier: str, alphabet: list[str]) -> str | None:
    """Декодирует payload по алфавиту, длина которого — степень двойки."""
    bits_per = len(alphabet).bit_length() - 1
    index = {ch: i for i, ch in enumerate(alphabet)}
    chunks = [
        format(index[ch], f"0{bits_per}b") for ch in carrier if ch in index
    ]
    if not chunks:
        return None
    data = _bits_to_bytes("".join(chunks))
    if not data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="ignore")
        return text or None


# Набор схем декодирования (документированные реальные варианты)
_SCHEMES: list[tuple[str, list[str]]] = [
    ("v2_octal", V2_ALPHABET),
    ("binary_zwsp", ["\u200b", "\u200c"]),
    ("binary_agent", ["\u200c", "\u2063"]),
    ("quaternary", ["\u200b", "\u200c", "\u200d", "\u2060"]),
    ("hex16", V2_ALPHABET + ["\u2061", "\u200e", "\u200f", "\u202f",
                             "\u2066", "\u2067", "\u2068", "\u2069"]),
]


def _printable_ratio(text: str) -> float:
    """Доля печатаемых/осмысленных символов в строке."""
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in " \t\n")
    return good / len(text)


def _try_zwsp_library(carrier: str) -> str | None:
    """Пробует декодировать через библиотеку zwsp-steg-py, если она есть."""
    try:
        import zwsp_steg  # type: ignore
    except ImportError:
        return None
    for mode in (getattr(zwsp_steg, "MODE_FULL", 1),
                 getattr(zwsp_steg, "MODE_ZWSP", 0)):
        try:
            result = zwsp_steg.decode(carrier, mode)
        except Exception:
            continue
        if result and _printable_ratio(result) > 0.8:
            return result
    return None


def decode_carrier(carrier: str) -> tuple[str, str] | None:
    """Пытается расшифровать невидимую последовательность всеми схемами.

    Returns:
        (расшифрованный_текст, имя_схемы) либо None, если ничего осмысленного.
    """
    candidates: list[tuple[str, str]] = []
    for name, alphabet in _SCHEMES:
        decoded = _decode_power_of_two(carrier, alphabet)
        if decoded and _printable_ratio(decoded) > 0.8:
            candidates.append((decoded, name))

    lib_result = _try_zwsp_library(carrier)
    if lib_result:
        candidates.append((lib_result, "zwsp-steg-py"))

    if not candidates:
        return None

    # Приоритет схеме, давшей метку с магическим префиксом, затем — самой длинной
    for decoded, name in candidates:
        if decoded.startswith(MARK_MAGIC):
            return decoded, name
    return max(candidates, key=lambda c: len(c[0]))


def build_mark(domain: str = MARK_DOMAIN, date: str | None = None) -> str:
    """Формирует текст метки автора: SHASH|domain|date|CRC32."""
    date = date or datetime.now().strftime("%Y-%m-%d")
    base = f"{MARK_MAGIC}|{domain}|{date}"
    checksum = format(zlib.crc32(base.encode("utf-8")) & 0xFFFFFFFF, "08X")
    return f"{base}|{checksum}"


def encode_mark(text: str | None = None) -> str:
    """Кодирует метку (по умолчанию свежую метку ShashevPro) в невидимые символы.

    Используется канонический алфавит V2. Этой функцией можно «штамповать»
    свой код, а сканер потом гарантированно распознает и проверит метку.
    """
    payload = text if text is not None else build_mark()
    data = payload.encode("utf-8")
    bits = "".join(format(byte, "08b") for byte in data)
    while len(bits) % 3:
        bits += "0"
    return "".join(
        V2_ALPHABET[int(bits[i : i + 3], 2)] for i in range(0, len(bits), 3)
    )


def verify_mark(decoded: str) -> dict | None:
    """Проверяет, является ли строка корректной меткой ShashevPro.

    Returns:
        Словарь с разобранными полями и флагом валидности контрольной суммы,
        либо None, если строка не похожа на метку формата SHASH.
    """
    parts = decoded.split("|")
    if len(parts) != 4 or parts[0] != MARK_MAGIC:
        return None
    base = "|".join(parts[:3])
    expected = format(zlib.crc32(base.encode("utf-8")) & 0xFFFFFFFF, "08X")
    return {
        "magic": parts[0],
        "domain": parts[1],
        "date": parts[2],
        "checksum": parts[3],
        "valid_checksum": expected == parts[3].upper(),
    }


# ---------------------------------------------------------------------------
# Очистка файла от невидимых символов (санитизация)
# ---------------------------------------------------------------------------


def clean_text(text: str) -> tuple[str, int]:
    """Удаляет из текста все подозрительные невидимые символы.

    Обычные tab / newline / carriage return сохраняются.

    Returns:
        (очищенный_текст, число_удалённых_символов).
    """
    kept: list[str] = []
    removed = 0
    for ch in text:
        if classify_char(ord(ch)) is not None:
            removed += 1
        else:
            kept.append(ch)
    return "".join(kept), removed


# ---------------------------------------------------------------------------
# Чтение файла с устойчивостью к кодировкам
# ---------------------------------------------------------------------------


def read_source(path: Path) -> tuple[str | None, str, str | None]:
    """Читает файл как байты и аккуратно декодирует, сохраняя символы.

    Невидимые символы важны на уровне байтов, поэтому файл читается как
    сырьё, а кодировка определяется явно (BOM → charset-normalizer → перебор).

    Returns:
        (текст | None, имя_кодировки, ошибка | None).
    """
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, "?", f"read_error: {exc}"

    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw.decode("utf-8-sig"), "utf-8-sig", None
        except UnicodeDecodeError:
            pass

    try:
        from charset_normalizer import from_bytes  # type: ignore

        best = from_bytes(raw).best()
        if best is not None:
            return str(best), str(best.encoding), None
    except ImportError:
        pass
    except Exception:
        pass

    for enc in ("utf-8", "utf-16", "cp1251", "latin-1"):
        try:
            return raw.decode(enc), enc, None
        except UnicodeDecodeError:
            continue

    return raw.decode("utf-8", errors="replace"), "utf-8(replace)", "decode_errors"


# ---------------------------------------------------------------------------
# Детекторы
# ---------------------------------------------------------------------------


class UnicodeDetector:
    """Ищет невидимые символы и расшифровывает скрытые метки."""

    def scan(self, text: str) -> list[Finding]:
        char_findings = self._scan_chars(text)
        carrier_findings = self._scan_carriers(text)
        # на строках, где payload расшифрован в метку/сообщение, не дублируем
        # сырую «×N невидимых символов» — показываем уже расшифрованный смысл
        decoded_lines = {f.line for f in carrier_findings if f.line is not None}
        char_findings = [f for f in char_findings if f.line not in decoded_lines]
        return self._aggregate_emoji(char_findings + carrier_findings)

    @staticmethod
    def _aggregate_emoji(findings: list[Finding]) -> list[Finding]:
        """Сворачивает разбросанные по файлу эмодзи-селекторы в одну строку.

        Каждый эмодзи (🗑️, ⬇️ …) несёт U+FE0F, и без свёртки получается куча
        одинаковых «инфо»-строк. Реально опасные невидимые символы не трогаем.
        """
        emoji = [f for f in findings if f.kind == "unicode_emoji_selector"]
        if len(emoji) <= 1:
            return findings
        others = [f for f in findings if f.kind != "unicode_emoji_selector"]
        lines = sorted({f.line for f in emoji if f.line})
        shown = ", ".join(str(x) for x in lines[:10])
        if len(lines) > 10:
            shown += " …"
        others.append(
            Finding(
                kind="unicode_emoji_selector",
                severity="info",
                title_key="finding.emoji_selector",
                line=lines[0] if lines else None,
                detail=f"×{len(emoji)} · U+FE0F · @ {shown}",
                rec_key="rec.emoji",
                extra={"count": len(emoji), "lines": lines},
            )
        )
        return others

    def _scan_chars(self, text: str) -> list[Finding]:
        """Посимвольный проход с группировкой подряд идущих символов.

        Длинная цепочка невидимых символов сворачивается в одну находку со
        счётчиком — иначе одна метка засыпала бы отчёт сотней строк.
        """
        findings: list[Finding] = []
        for lineno, line in enumerate(text.split("\n"), start=1):
            for run in self._char_runs(line):
                findings.append(self._run_finding(run, lineno))
        return findings

    @staticmethod
    def _char_runs(line: str) -> Iterable[list[tuple[int, int, str, str]]]:
        """Возвращает серии подряд идущих подозрительных символов в строке.

        Каждый элемент серии: (столбец, кодпойнт, категория, опасность).
        """
        run: list[tuple[int, int, str, str]] = []
        for col, ch in enumerate(line, start=1):
            cls = classify_char(ord(ch))
            if cls is None:
                if run:
                    yield run
                    run = []
                continue
            kind, severity = cls
            run.append((col, ord(ch), kind, severity))
        if run:
            yield run

    @staticmethod
    def _run_finding(
        run: list[tuple[int, int, str, str]], lineno: int
    ) -> Finding:
        col = run[0][0]
        worst = max(run, key=lambda r: SEVERITY_ORDER[r[3]])
        severity = worst[3]
        categories = sorted({r[2] for r in run})

        if len(run) == 1:
            cp = run[0][1]
            category = run[0][2]
            rec = "rec.emoji" if category == "emoji_selector" else "rec.invisible"
            return Finding(
                kind=f"unicode_{category}",
                severity=severity,
                title_key=f"finding.{category}",
                line=lineno,
                column=col,
                detail=char_name(cp),
                rec_key=rec,
                extra={"codepoint": cp, "category": category},
            )

        distinct = sorted({r[1] for r in run})
        names = ", ".join(char_name(cp) for cp in distinct[:6])
        if len(distinct) > 6:
            names += " …"
        return Finding(
            kind="unicode_run",
            severity=severity,
            title_key="finding.invisible_run",
            line=lineno,
            column=col,
            detail=f"×{len(run)} · {names}",
            rec_key="rec.invisible",
            extra={
                "count": len(run),
                "categories": categories,
                "codepoints": distinct,
            },
        )

    def _scan_carriers(self, text: str) -> list[Finding]:
        """Выделяет цепочки невидимых символов и пытается их расшифровать."""
        findings: list[Finding] = []
        for start, carrier in self._iter_runs(text):
            if len(carrier) < 8:  # меньше байта смысла не несёт
                continue
            decoded = decode_carrier(carrier)
            if decoded is None:
                continue
            payload, scheme = decoded
            lineno = text.count("\n", 0, start) + 1
            mark = verify_mark(payload)
            if mark is not None:
                findings.append(self._mark_finding(mark, scheme, lineno, payload))
            else:
                findings.append(
                    Finding(
                        kind="hidden_string",
                        severity="high",
                        title_key="finding.hidden_string",
                        line=lineno,
                        detail=payload[:200],
                        rec_key="rec.hidden_string",
                        extra={"scheme": scheme, "length": len(payload)},
                    )
                )
        return findings

    @staticmethod
    def _mark_finding(
        mark: dict, scheme: str, lineno: int, payload: str
    ) -> Finding:
        is_shashevpro = mark["domain"] == MARK_DOMAIN
        severity = "info" if (is_shashevpro and mark["valid_checksum"]) else "medium"
        return Finding(
            kind="author_mark",
            severity=severity,
            title_key="finding.author_mark",
            line=lineno,
            detail=payload,
            rec_key=None if is_shashevpro else "rec.foreign_mark",
            extra={"scheme": scheme, **mark},
        )

    @staticmethod
    def _iter_runs(text: str) -> Iterable[tuple[int, str]]:
        """Генерирует (позиция_начала, цепочка) для серий стего-символов."""
        run_start = -1
        run_chars: list[str] = []
        for i, ch in enumerate(text):
            if ord(ch) in _STEGO_CAPABLE:
                if run_start == -1:
                    run_start = i
                run_chars.append(ch)
            elif run_chars:
                yield run_start, "".join(run_chars)
                run_start, run_chars = -1, []
        if run_chars:
            yield run_start, "".join(run_chars)


class HomoglyphDetector:
    """Ищет слова со смешанными алфавитами (латиница + кириллица/греческий).

    Перед поиском нейтрализует экранированные последовательности (\\n, \\t,
    \\xNN, \\uNNNN …): иначе буква после бэкслэша (например, n из \\n) склеивается
    со следующим кириллическим словом и выглядит как гомоглиф-подмена.
    """

    _WORD_RE = re.compile(r"[^\W\d_]{2,}", re.UNICODE)
    _ESCAPE_RE = re.compile(
        r"\\[0-7]{1,3}"
        r"|\\x[0-9A-Fa-f]{2}"
        r"|\\u[0-9A-Fa-f]{4}"
        r"|\\U[0-9A-Fa-f]{8}"
        r"|\\N\{[^}]*\}"
        r"|\\."
    )

    @staticmethod
    def _script(cp: int) -> str | None:
        if (0x41 <= cp <= 0x5A) or (0x61 <= cp <= 0x7A):
            return "Latin"
        if 0x400 <= cp <= 0x4FF:
            return "Cyrillic"
        if 0x370 <= cp <= 0x3FF:
            return "Greek"
        return None

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.split("\n"), start=1):
            # экранирование заменяем пробелами той же длины — столбцы не сдвигаются
            neutral = self._ESCAPE_RE.sub(lambda m: " " * len(m.group()), line)
            for match in self._WORD_RE.finditer(neutral):
                word = match.group()
                scripts = {s for s in (self._script(ord(c)) for c in word) if s}
                if len(scripts) > 1:
                    findings.append(
                        Finding(
                            kind="homoglyph",
                            severity="high",
                            title_key="finding.homoglyph",
                            line=lineno,
                            column=match.start() + 1,
                            detail=f"{word}  ({' + '.join(sorted(scripts))})",
                            rec_key="rec.homoglyph",
                            extra={"word": word, "scripts": sorted(scripts)},
                        )
                    )
        return findings


def shannon_entropy(value: str) -> float:
    """Энтропия Шеннона строки — мера «случайности» (для поиска ключей)."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def mask_secret(value: str, head: int = 6, tail: int = 4) -> str:
    """Маскирует середину секрета, чтобы не светить его в отчёте целиком."""
    if len(value) <= head + tail:
        return value[:2] + "***"
    return f"{value[:head]}…{value[-tail:]}"


class SecretDetector:
    """Ищет ключи API, токены, пароли и приватные ключи."""

    # (имя, регэксп, опасность)
    _PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
        ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
        ("telegram_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), "critical"),
        ("stripe_live", re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{16,}\b"), "critical"),
        ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"), "critical"),
        ("github_pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{60,}\b"), "critical"),
        ("google_api", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
        ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
        (
            "private_key",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
            "critical",
        ),
        (
            "jwt",
            re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
            "medium",
        ),
    ]

    _ASSIGN_RE = re.compile(
        r"(?i)\b(api[_-]?key|secret[_-]?key|secret|token|passwd|password|pwd|"
        r"access[_-]?key|auth[_-]?token)\b\s*[:=]\s*['\"]([^'\"\n]{6,})['\"]"
    )

    _PLACEHOLDERS = {
        "your_key_here", "changeme", "xxxxxx", "placeholder", "example",
        "todo", "secret", "password", "<your", "...",
    }

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        line_starts = self._line_index(text)

        for name, pattern, severity in self._PATTERNS:
            for match in pattern.finditer(text):
                lineno = self._lineno(line_starts, match.start())
                findings.append(
                    Finding(
                        kind="secret",
                        severity=severity,
                        title_key=f"secret.{name}",
                        line=lineno,
                        detail=mask_secret(match.group()),
                        rec_key="rec.secret",
                        extra={"secret_type": name},
                    )
                )

        for match in self._ASSIGN_RE.finditer(text):
            value = match.group(2)
            # значение с пробелом — это фраза/подпись ("Не найден", "Not set"),
            # а не секрет: настоящие ключи/токены/пароли пробелов не содержат
            if any(ch.isspace() for ch in value):
                continue
            lineno = self._lineno(line_starts, match.start())
            low = value.lower()
            if any(ph in low for ph in self._PLACEHOLDERS):
                severity = "low"
            elif shannon_entropy(value) >= 3.5 and len(value) >= 12:
                severity = "high"
            else:
                severity = "medium"
            findings.append(
                Finding(
                    kind="secret",
                    severity=severity,
                    title_key="secret.generic",
                    line=lineno,
                    detail=f"{match.group(1)} = {mask_secret(value)}",
                    rec_key="rec.secret",
                    extra={"secret_type": "generic", "key": match.group(1)},
                )
            )
        return findings

    @staticmethod
    def _line_index(text: str) -> list[int]:
        starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                starts.append(i + 1)
        return starts

    @staticmethod
    def _lineno(starts: list[int], pos: int) -> int:
        import bisect

        return bisect.bisect_right(starts, pos)


class EncodedStringDetector:
    """Ищет закодированные строки (Base64 / Hex) и пытается их раскрыть."""

    _B64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
    _HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")

    def scan(self, text: str) -> list[Finding]:
        import base64
        import binascii

        findings: list[Finding] = []
        line_starts = SecretDetector._line_index(text)

        for match in self._B64_RE.finditer(text):
            token = match.group()
            if len(token) % 4 != 0:
                continue
            try:
                raw = base64.b64decode(token, validate=True)
                decoded = raw.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if _printable_ratio(decoded) < 0.85 or len(decoded) < 3:
                continue
            findings.append(self._make(line_starts, match.start(), decoded, "base64"))

        for match in self._HEX_RE.finditer(text):
            token = match.group()
            if len(token) % 2 != 0:
                continue
            try:
                raw = bytes.fromhex(token)
                decoded = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if _printable_ratio(decoded) < 0.85 or len(decoded) < 3:
                continue
            findings.append(self._make(line_starts, match.start(), decoded, "hex"))

        return findings

    @staticmethod
    def _make(starts: list[int], pos: int, decoded: str, enc: str) -> Finding:
        return Finding(
            kind="encoded_string",
            severity="low",
            title_key="finding.encoded_string",
            line=SecretDetector._lineno(starts, pos),
            detail=f"[{enc}] → {decoded[:160]}",
            rec_key="rec.encoded_string",
            extra={"encoding": enc, "decoded": decoded[:200]},
        )


class WatermarkDetector:
    """Ищет классические водяные знаки и метки в комментариях."""

    _DUNDER_RE = re.compile(
        r"^\s*(__author__|__copyright__|__credits__|__maintainer__)\s*=\s*"
        r"['\"]([^'\"\n]+)['\"]",
        re.MULTILINE,
    )
    _KEYWORDS = ("created by", "author:", "copyright", "©", "(c)", "written by",
                 "автор", "разработал", "watermark", "fingerprint")

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        starts = SecretDetector._line_index(text)

        for match in self._DUNDER_RE.finditer(text):
            findings.append(
                Finding(
                    kind="watermark",
                    severity="info",
                    title_key="finding.watermark_dunder",
                    line=SecretDetector._lineno(starts, match.start()),
                    detail=f"{match.group(1)} = {match.group(2)}",
                    extra={"name": match.group(1), "value": match.group(2)},
                )
            )

        findings.extend(self._scan_comments(text))
        return findings

    def _scan_comments(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            tokens = tokenize.generate_tokens(io.StringIO(text).readline)
            comments = [
                (tok.start[0], tok.string)
                for tok in tokens
                if tok.type == tokenize.COMMENT
            ]
        except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
            return findings

        for lineno, comment in comments:
            low = comment.lower()
            if any(kw in low for kw in self._KEYWORDS):
                clean_comment = clean_text(comment)[0].strip()
                findings.append(
                    Finding(
                        kind="watermark",
                        severity="info",
                        title_key="finding.watermark_comment",
                        line=lineno,
                        detail=clean_comment[:160],
                        extra={},
                    )
                )
        return findings


class AstAnalyzer(ast.NodeVisitor):
    """Анализирует синтаксическое дерево: опасные вызовы, импорты, сеть.

    Калибровка: легальные импорты и сетевые вызовы — это контекст
    (severity "info"), а не угроза. Угрозой остаётся только реально опасное
    и/или скрытое: exec/eval с декодированием, запуск команд оболочки.
    Сеть определяется по модулю/объекту вызова (requests./urllib./socket.…),
    а не по имени метода, поэтому обычный dict.get() / os.environ.get() больше
    не ловится. Повторы (импорт, десятки сетевых вызовов) сводятся в одну строку.
    """

    _DANGEROUS_CALLS = {"eval", "exec", "compile", "__import__"}
    _DECODERS = {"b64decode", "b16decode", "b32decode", "a85decode",
                 "decompress", "loads", "unhexlify", "decode"}
    _SENSITIVE_IMPORTS = frozenset({
        "socket", "subprocess", "ctypes", "marshal", "pickle", "telnetlib",
        "ftplib", "paramiko", "requests", "urllib", "http", "httpx",
        "aiohttp", "urllib3", "websocket", "websockets", "pty", "shutil",
    })
    _NET_MODULES = frozenset({
        "requests", "urllib", "httpx", "aiohttp", "http", "urllib3",
        "ftplib", "telnetlib", "socket", "websocket", "websockets",
    })
    _NET_DISTINCT = frozenset({"urlopen", "create_connection"})

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self._imports: dict[str, int] = {}
        self._net_calls: list[tuple[int, str]] = []
        self._shell_calls: list[tuple[int, str]] = []

    def analyze(self, text: str) -> list[Finding]:
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            return [
                Finding(
                    kind="parse_error",
                    severity="low",
                    title_key="finding.parse_error",
                    line=exc.lineno,
                    detail=str(exc.msg),
                    rec_key="rec.parse_error",
                )
            ]
        self.findings = []
        self._imports = {}
        self._net_calls = []
        self._shell_calls = []
        self.visit(tree)
        self._emit_aggregated()
        return self.findings

    # -- импорты (накапливаем, потом сводим) -----------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._note_import(alias.name.split(".")[0], node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._note_import(node.module.split(".")[0], node.lineno)
        self.generic_visit(node)

    def _note_import(self, root: str, lineno: int) -> None:
        if root in self._SENSITIVE_IMPORTS and root not in self._imports:
            self._imports[root] = lineno

    # -- вызовы ----------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        parts = self._dotted_parts(node.func)
        name = parts[-1] if parts else self._call_name(node.func)
        root = parts[0] if parts else ""

        # exec/eval/compile/__import__ — только встроенные (bare-вызов),
        # чтобы не путать с re.compile, obj.eval и т.п.
        if isinstance(node.func, ast.Name) and node.func.id in self._DANGEROUS_CALLS:
            self._check_dangerous_call(node, node.func.id)

        if self._is_network(parts, name):
            label = ".".join(parts) if parts else name
            self._net_calls.append((node.lineno, label))

        shell_true = self._has_shell_true(node)
        if (name in {"system", "popen"} and root == "os") or (
            name in {"run", "call", "Popen", "check_output", "check_call"}
            and shell_true
        ):
            label = f"{'.'.join(parts) if parts else name}(...)"
            self._shell_calls.append((node.lineno, label))
        self.generic_visit(node)

    def _check_dangerous_call(self, node: ast.Call, func_name: str) -> None:
        nested_decoder = self._contains_decoder(node)
        non_literal = bool(node.args) and not all(
            isinstance(a, ast.Constant) for a in node.args
        )
        if nested_decoder:
            severity, title = "critical", "finding.exec_decoded"
        elif non_literal:
            severity, title = "high", "finding.exec_dynamic"
        else:
            severity, title = "medium", "finding.exec_literal"
        self.findings.append(
            Finding(
                kind="dangerous_exec",
                severity=severity,
                title_key=title,
                line=node.lineno,
                detail=self._snippet(node),
                rec_key="rec.dangerous_exec",
                extra={"call": func_name},
            )
        )

    def _is_network(self, parts: list[str] | None, name: str) -> bool:
        """Сеть — по модулю/объекту вызова, а не по имени метода.

        requests.get / urllib.request.urlopen / socket.socket ловятся,
        безобидные dict.get() и os.environ.get() — нет.
        """
        if name in self._NET_DISTINCT:
            return True
        if parts and parts[0] in self._NET_MODULES:
            return True
        return False

    # -- сводки ----------------------------------------------------------

    def _emit_aggregated(self) -> None:
        """Сворачивает повторяющиеся импорты и сетевые вызовы в сводку."""
        for module, lineno in sorted(self._imports.items(),
                                     key=lambda kv: kv[1]):
            self.findings.append(
                Finding(
                    kind="sensitive_import",
                    severity="info",
                    title_key="finding.sensitive_import",
                    line=lineno,
                    detail=module,
                    rec_key="rec.sensitive_import",
                    extra={"module": module},
                )
            )
        if self._net_calls:
            lines = sorted({ln for ln, _ in self._net_calls})
            labels = sorted({lbl for _, lbl in self._net_calls})
            shown_lines = ", ".join(str(x) for x in lines[:10])
            if len(lines) > 10:
                shown_lines += " …"
            shown_labels = ", ".join(labels[:6])
            if len(labels) > 6:
                shown_labels += " …"
            self.findings.append(
                Finding(
                    kind="network_call",
                    severity="info",
                    title_key="finding.network_calls",
                    line=lines[0],
                    detail=f"×{len(self._net_calls)} · {shown_labels} · @ {shown_lines}",
                    rec_key="rec.network_call",
                    extra={"count": len(self._net_calls), "lines": lines},
                )
            )
        if self._shell_calls:
            lines = sorted({ln for ln, _ in self._shell_calls})
            labels = sorted({lbl for _, lbl in self._shell_calls})
            shown_lines = ", ".join(str(x) for x in lines[:10])
            if len(lines) > 10:
                shown_lines += " …"
            shown_labels = ", ".join(labels[:6])
            if len(labels) > 6:
                shown_labels += " …"
            self.findings.append(
                Finding(
                    kind="shell_exec",
                    severity="medium",
                    title_key="finding.shell_execs",
                    line=lines[0],
                    detail=f"×{len(self._shell_calls)} · {shown_labels} · @ {shown_lines}",
                    rec_key="rec.shell_exec",
                    extra={"count": len(self._shell_calls), "lines": lines},
                )
            )

    # -- вспомогательные -------------------------------------------------

    @staticmethod
    def _dotted_parts(func: ast.expr) -> list[str] | None:
        """requests.get -> ['requests','get']; dict.get -> ['dict','get']."""
        parts: list[str] = []
        cur: ast.expr = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            parts.reverse()
            return parts
        return None

    @staticmethod
    def _call_name(func: ast.expr) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""

    def _contains_decoder(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if self._call_name(child.func) in self._DECODERS:
                    return True
        return False

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                return bool(kw.value.value)
        return False

    @staticmethod
    def _snippet(node: ast.AST, limit: int = 120) -> str:
        try:
            text = ast.unparse(node)
        except Exception:
            return "<...>"
        return text if len(text) <= limit else text[:limit] + "…"


# ---------------------------------------------------------------------------
# Оркестратор сканирования
# ---------------------------------------------------------------------------

# Каталоги, которые по умолчанию пропускаются при обходе папки
DEFAULT_IGNORE = {
    ".git", "__pycache__", ".venv", "venv", "env", "node_modules",
    "build", "dist", ".idea", ".mypy_cache", ".pytest_cache", "site-packages",
}


class Scanner:
    """Обходит файлы и применяет все детекторы. Потоковый и многопоточный."""

    def __init__(self, max_workers: int = 4) -> None:
        self.max_workers = max_workers
        self._detectors = [
            UnicodeDetector(),
            HomoglyphDetector(),
            SecretDetector(),
            EncodedStringDetector(),
            WatermarkDetector(),
        ]

    def collect_files(self, target: str | Path) -> list[Path]:
        """Собирает список .py / .pyw файлов из файла или папки."""
        path = Path(target)
        if path.is_file():
            return [path]
        files: list[Path] = []
        for item in path.rglob("*"):
            if item.suffix.lower() not in (".py", ".pyw"):
                continue
            if any(part in DEFAULT_IGNORE for part in item.parts):
                continue
            files.append(item)
        return sorted(files)

    def scan_file(self, path: Path) -> FileReport:
        """Сканирует один файл всеми детекторами."""
        text, encoding, error = read_source(path)
        report = FileReport(path=str(path), encoding=encoding, error=error)
        if text is None:
            return report
        for detector in self._detectors:
            try:
                report.findings.extend(detector.scan(text))
            except Exception as exc:  # детектор не должен ронять всё сканирование
                report.findings.append(
                    Finding(
                        kind="detector_error",
                        severity="info",
                        title_key="finding.detector_error",
                        detail=f"{type(detector).__name__}: {exc}",
                    )
                )
        try:
            report.findings.extend(AstAnalyzer().analyze(text))
        except Exception as exc:
            report.findings.append(
                Finding(
                    kind="detector_error",
                    severity="info",
                    title_key="finding.detector_error",
                    detail=f"AstAnalyzer: {exc}",
                )
            )
        report.findings.sort(
            key=lambda f: (-SEVERITY_ORDER[f.severity], f.line or 0)
        )
        return report

    def scan(
        self,
        target: str | Path,
        progress: Callable[[int, int, str], None] | None = None,
    ) -> ScanReport:
        """Сканирует цель целиком. progress(done, total, path) — колбэк прогресса."""
        files = self.collect_files(target)
        report = ScanReport()
        total = len(files)
        if total == 0:
            report.finished_at = datetime.now()
            return report

        done = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {pool.submit(self.scan_file, f): f for f in files}
            for future in as_completed(future_map):
                file_report = future.result()
                report.file_reports.append(file_report)
                done += 1
                if progress is not None:
                    progress(done, total, file_report.path)

        report.file_reports.sort(
            key=lambda fr: (-SEVERITY_ORDER[fr.max_severity], fr.path)
        )
        report.finished_at = datetime.now()
        return report
