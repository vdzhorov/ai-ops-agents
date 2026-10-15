# ai-ops-agents

Собствени AI инструменти за ops задачи. Всеки инструмент е модул в `aiops/agents/`, а общите части
(LLM providers, маскиране, Ansible) са в `aiops/core/`.

```
aiops/
  __main__.py              # python -m aiops <tool> ...
  core/
    config.py              # настройки от .env
    llm.py                 # OllamaProvider + AnthropicProvider (общ интерфейс complete_json)
    masking.py             # маскиране на IP/hostname преди изпращане към Claude
    ansible_runner.py      # пускане на playbook-ове от venv-а
  agents/
    cve_watch/             # инструмент #1
tests/
```

## Инсталация

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env          # и попълни ANTHROPIC_API_KEY
ollama pull gemma4:e4b        # локален модел за triage
```

## cve-watch

Проверява кои известни уязвимости **реално засягат** конфигурацията на сървърите, вместо само да изброява CVE номера.

### Как работи

1. **Събиране (read-only).** Ansible пуска `collect.sh` през модула `raw`, т.е. чист SSH exec. На хоста не се копират файлове
   и не е нужен Python. Скриптът само чете: списък пакети (dpkg/rpm), слушащи сокети (`ss`), кои
   изпълними файлове и **споделени библиотеки** са заредени от работещи процеси (`/proc/*/maps`), заредени kernel модули
   и работещи услуги.
2. **Употреба на пакетите.** Всеки пакет получава ниво:
   `network-exposed` (зареден от процес, който слуша навън), `kernel-running`, `local-listener`, `running`, `installed`
   или `kernel-inactive`. Например libssl3 → openssl се маркира като network-exposed, защото го зарежда nginx на 0.0.0.0:443.
3. **Съпоставяне.** [OSV.dev](https://osv.dev) намира уязвимостите по точна версия, с правилата за сравнение на самата
   дистрибуция. Поддържат се Debian, Ubuntu, Rocky и Alma, а RHEL/CentOS/Oracle се проверяват срещу Alma advisories.
   Severity идва първо от рейтинга на дистрибуцията, а при липса от CVSS.
   **По подразбиране (`--scope used`) се проверяват само пакети, които реално се ползват.** На типичен сървър около 80%
   от пакетите са само инсталирани. `--scope all` проверява и тях, например веднъж седмично.
   **Работещият kernel се проверява винаги** (`--no-kernel` го изключва). Той има хиляди CVE-та: първото пускане
   изтегля записите им (няколко минути), после се теглят само новите или променените.
4. **Филтър.** Взимат се severity ≥ `--min-severity` (по подразбиране high). Към LLM отиват само първите
   `--max-per-package` (по подразбиране 8) за пакет, подредени по severity, мрежов attack vector, наличен fix и CVSS.
   Останалите се обобщават в отчета. Хостове с еднакъв пакет и еднакъв контекст се оценяват с **една** заявка.
5. **Оценка** (`--provider`):
   - `hybrid` (по подразбиране): локалният gemma4:e4b прави triage на всичко безплатно. Claude преоценява само това,
     което triage не е отхвърлил като `unlikely`/`not_affected`. Има лимит `--claude-budget` (по подразбиране 30 заявки).
   - `anthropic`: Claude оценява всичко.
   - `ollama`: само локален модел, нищо не излиза от машината. По-бавно и по-неточно.
   - `none`: без LLM, само правила (severity + употреба).
6. **Памет между пусканията.** Оценките се пазят в `.cache/assessments.json`. При следващо пускане моделът вижда само
   **новите** уязвимости или такива, чийто контекст се е променил: нов порт, нова версия, излязла поправка, друг severity.
   В отчета новите са маркирани с ★ НОВО. С `--fresh` всичко се преоценява наново. OSV записите също се кешират и се
   теглят наново само когато OSV отчете промяна.
7. **Изход.** На stdout в момента на оценяване се печатат новите важни находки. Накрая се показва таблица с всички
   текущи важни находки, а Markdown отчетът се записва в `reports/`.

Verdict-и: `affected`, `likely`, `possible` (важни) и `unlikely`, `not_affected` (отхвърлени). Всяка важна находка има
причина, действие и **read-only** команда за ръчна проверка.

### Употреба

```sh
# Ansible inventory (препоръчително с --become за пълна картина на процесите)
.venv/bin/python -m aiops cve-watch -i ~/infra/inventory.ini -b
.venv/bin/python -m aiops cve-watch -i ~/infra/inventory.ini -l webservers -b

# Един сървър
.venv/bin/python -m aiops cve-watch --host root@10.0.0.5
.venv/bin/python -m aiops cve-watch --host deploy@web1.example.com:2222 -b

# Запази суровите данни и после пускай анализа офлайн (без нов SSH)
.venv/bin/python -m aiops cve-watch -i inv.ini -b --save-facts facts/
.venv/bin/python -m aiops cve-watch --facts-dir facts/ --provider anthropic

# Ръчен списък пакети ("име версия" на ред; за Debian/Ubuntu: source package)
.venv/bin/python -m aiops cve-watch --packages pkgs.txt --ecosystem "Debian:12"

# Само локално, без Claude
.venv/bin/python -m aiops cve-watch -i inv.ini -b --provider ollama
```

Полезни флагове: `--scope all`, `--no-kernel`, `--fresh`, `--min-severity medium`, `--include-unknown`, `--max-per-package 15`, `--claude-budget 10`,
`--claude-model claude-haiku-5-5`, `--include-inactive-kernels`, `--no-mask`, `--lang en`.

### Модели и разход

- **Claude** (по подразбиране `claude-opus-5-5` с `effort=low`) дава окончателната оценка. Всяка заявка носи 6 уязвимости
  с общ контекст. Системният prompt е маркиран за prompt caching. Включен е server-side refusal fallback, тъй като
  security съдържанието понякога активира classifier-ите. В края се показва приблизителна цена.
  `ANTHROPIC_MODEL=claude-haiku-5-5` е около 40 пъти по-евтин на токен.
- **gemma4:e4b** през Ollama прави triage. На 16 GB MacBook върви с около 5–6 сек. на уязвимост. Ако Ollama runner-ът
  не поддържа structured output (някои MLX builds), JSON schema-та автоматично се подава в prompt-а.

### Какво излиза от машината

- Към **OSV.dev**: имена и версии на пакети, без hostname и IP.
- Към **Claude**: ОС, kernel, имена на пакети и процеси, слушащи портове и текстовете на уязвимостите.
  Hostname-ите и всички IP адреси без loopback/wildcard се заменят с `<host-N>`/`<ip-N>`, а след отговора се връщат
  обратно локално. Конфигурационни файлове не се събират.

### Ограничения

- Пакети само от системния пакетен мениджър. pip/npm/контейнери засега не се покриват.
- Без root (`-b`) се виждат само процесите на SSH потребителя, затова оценката на употребата е непълна.
- Derivatives без собствен OSV feed (Mint, Proxmox и др.) се пропускат.

### Тестове

```sh
.venv/bin/python -m unittest discover tests
```

## changelog

Показва наличните версии на даден софтуер, последните версии и **всички промени между две версии, включително
тези в междинните версии**. Връща суровите release notes и AI обобщение.

| Софтуер | Как се задава | Източник |
|---|---|---|
| JumpServer | `jumpserver` | GitHub releases |
| Comet Backup | `comet` | docs.cometbackup.com (sitemap + страница за всяка версия) |
| OpenStack (цял) | `openstack` | серии (2025.1 Epoxy…) от `openstack/releases` + Release Highlights на releases.openstack.org |
| OpenStack проект | `nova`, `neutron`, … или `openstack:<проект>` | `openstack/releases` (версии) + docs.openstack.org/releasenotes (reno) |
| Всеки проект с GitHub releases | `github:<owner>/<repo>` | GitHub releases, а при липса на такива tags |

```sh
.venv/bin/python -m aiops changelog versions jumpserver            # последните 10 версии (без AI)
.venv/bin/python -m aiops changelog versions jumpserver --all      # всички версии
.venv/bin/python -m aiops changelog versions comet --line voyager -n 20
.venv/bin/python -m aiops changelog versions openstack             # серии на OpenStack (2026.2, 2026.1, ...)
.venv/bin/python -m aiops changelog diff openstack 2024.1 2025.2    # highlights на всички серии между тях
.venv/bin/python -m aiops changelog latest nova                    # последна версия общо и по линия/серия
.venv/bin/python -m aiops changelog diff jumpserver v4.10.15 v5.0.0
.venv/bin/python -m aiops changelog diff comet 26.8.5               # до последната версия
.venv/bin/python -m aiops changelog diff nova caracal epoxy         # OpenStack: серия = последната ѝ версия
.venv/bin/python -m aiops changelog diff nova 29.4.0 31.3.1 --raw --provider none
```

**Интервал.** `diff A B` включва всяка публикувана версия, за която `A < версия ≤ B`, подредени по номер. Така при
паралелни линии влизат и поддръжните версии, които попадат между двете. Например между `v4.10.15` и `v5.0.0` влизат
`v4.10.16…v4.10.19`, но не `v3.10.x`. Pre-release версиите (rc, beta) се включват с `--pre`. При OpenStack подредбата е
първо по серия, защото преди 2015 г. версиите се номерираха по година.

**Изход.** На екрана се показват списък с версиите в интервала и AI обобщение по категории: breaking changes,
security, бележки за ъпгрейд, deprecations, нови възможности, важни поправки, плюс риск и препоръки. В
`reports/changelog-*.md` се записват обобщението и **пълните release notes** на всяка версия. С `--raw` пълният текст
се печата и на екрана.

**AI.** `--provider auto` (по подразбиране) ползва Claude, ако има `ANTHROPIC_API_KEY`, а иначе локалния gemma.
`none` спира AI частта. При голям интервал notes се обработват на части и накрая се прави едно общо обобщение.

**Кеш.** Отговорите се пазят в `.cache/web/`. Списъците с версии се обновяват на няколко часа, а release notes на
отделните версии се пазят по-дълго. Без `GITHUB_TOKEN` GitHub позволява 60 заявки на час.

## Нов инструмент

1. `aiops/agents/<name>/cli.py` с `main(argv) -> int`
2. Регистрирай го в `TOOLS` в `aiops/__main__.py`
3. Ползвай `aiops.core.llm` за модели, `aiops.core.ansible_runner` за събиране от хостове, `aiops.core.masking` за данни,
   които излизат навън.
