# Участие в проекте · Contributing

## 🇷🇺 Русский

Спасибо за интерес к Инквизитору! Репозиторием управляет автор (ShashevPro). Внести вклад
можно так:

1. **Нашли ошибку или есть идея?** Откройте *Issue* — для этого права записи не нужны.
2. **Хотите предложить правку кода?**
   - Сделайте *Fork* репозитория (кнопка «Fork» — копия появится в вашем аккаунте).
   - Внесите изменения в своей копии (желательно в отдельной ветке).
   - Откройте *Pull Request* в этот репозиторий.
   - Автор посмотрит изменения и решит, принимать ли их (*merge*).

Так автор сохраняет контроль над проектом, а любой желающий может предложить улучшение.

**Перед правкой движка:** не возвращайте ложные срабатывания. Калибровка специально
настроена так, чтобы `dict.get` не считался сетью, `re.compile` — опасным `compile`,
экранирование (`\n`) — гомоглифом, эмодзи — угрозой, а подписи с пробелом — секретом.

## 🇬🇧 English

Thanks for your interest in Inquisitor! The repository is maintained by the author
(ShashevPro). You can contribute like this:

1. **Found a bug or have an idea?** Open an *Issue* — no write access required.
2. **Want to propose a code change?**
   - *Fork* the repository (the "Fork" button — a copy appears in your account).
   - Make your changes in your copy (ideally on a separate branch).
   - Open a *Pull Request* to this repository.
   - The author will review and decide whether to *merge* it.

This keeps the author in control of the project while letting anyone propose improvements.

**Before changing the engine:** do not reintroduce false positives. The calibration is
deliberately tuned so that `dict.get` is not treated as network, `re.compile` is not the
dangerous `compile`, escape sequences (`\n`) are not homoglyphs, emoji are not threats,
and whitespace-containing labels are not secrets.
