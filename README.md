# MikroTik CHR — бан по failed login (аналог fail2ban)

**RouterOS 7.x** (проверено на **7.23.1 stable**)

Бан IP после неудачных попыток входа по **логам** — не по числу TCP-подключений. Успешный логин счётчик не увеличивает.

Файлы в репозитории:

- `mikrotik-ban-failed-logins-source.txt` — тело скрипта для Winbox
- `mikrotik-ban-failed-logins.rsc` — импорт через терминал

---

## Как работает

| Шаг | Поведение |
|-----|-----------|
| 1–4 неудачных входа | IP в `login-strike` (timeout **1 час**, comment = номер попытки) |
| 5+ неудачных входов | IP в `login-failed-ban` (timeout **1 день**) |
| Firewall | Drop в `chain=input` для `login-failed-ban` |
| Scheduler | Скрипт раз в **1 минуту** |
| Whitelist | IP из `mgmt_trusted` не банятся |

Скрипт запоминает последнюю обработанную запись лога (`lastLogIdx`). Если она исчезла из буфера — автоматический сброс и продолжение работы.

Фильтр: `topics~"critical" and message~"login failure for user"` — только реальные failed login, без дампов исходника скрипта из лога.

---

## Установка

Подставьте свои значения вместо плейсхолдеров:

| Плейсхолдер | Пример |
|-------------|--------|
| `YOUR_LAN_SUBNET` | `10.0.0.0/24` |
| `YOUR_OFFICE_IP` | `203.0.113.10` |
| `YOUR_MOBILE_IP` | `203.0.113.20` |

### 1. Доверенные IP (whitelist)

```routeros
/ip firewall address-list
add list=mgmt_trusted address=YOUR_LAN_SUBNET comment="LAN/VPN"
add list=mgmt_trusted address=YOUR_OFFICE_IP/32 comment="management IP office"
add list=mgmt_trusted address=YOUR_MOBILE_IP/32 comment="management IP mobile/APN"
```

### 2. Drop-правило для забаненных

```routeros
/ip firewall filter
add chain=input src-address-list=login-failed-ban action=drop comment="Drop IPs banned for failed logins"
move [find comment="Drop IPs banned for failed logins"] destination=0
```

### 3. Создать скрипт (пустой source)

```routeros
/system script add name=ban-failed-logins owner=YOUR_USER policy=read,write,test,policy,sniff,sensitive comment="ban failed logins" source=""
```

### 4. Расписание (раз в минуту)

```routeros
/system scheduler add name=ban-failed-logins interval=1m on-event=ban-failed-logins policy=read,write,test,policy,sniff,sensitive
```

### 5. Вставить тело скрипта

**Winbox:** System → Scripts → `ban-failed-logins` → **Source** → вставить код ниже → **OK**.

Кнопка **Run Script** — ожидается: `Action Run Script OK`.

На CHR после вставки через терминал иногда флаг `I` (INVALID) — если Run OK, обычно это косметика. Надёжнее Winbox или `/import` файла `.rsc`.

### Тело скрипта

```routeros
:global lastLogIdx
:local banList "login-failed-ban"
:local strikeList "login-strike"
:local trustList "mgmt_trusted"
:local maxAttempts 5
:local banTimeout 1d
:if ([:typeof $lastLogIdx] = "nothing") do={ :set lastLogIdx "" }
:local foundLast 0
:foreach logIdx in=[/log find where topics~"critical" and message~"login failure for user"] do={
  :if ($logIdx = $lastLogIdx) do={ :set foundLast 1 }
}
:if ($lastLogIdx != "" && $foundLast = 0) do={ :set lastLogIdx "" }
:local processNew 0
:if ($lastLogIdx = "") do={ :set processNew 1 }
:foreach logIdx in=[/log find where topics~"critical" and message~"login failure for user"] do={
  :if ($processNew = 0) do={
    :if ($logIdx = $lastLogIdx) do={ :set processNew 1 }
  } else={
    :local logMsg [/log get $logIdx message]
    :local posFrom [:find $logMsg " from "]
    :local posVia [:find $logMsg " via "]
    :if ([:typeof $posFrom] != "nothing" && [:typeof $posVia] != "nothing") do={
      :local srcAddr [:pick $logMsg ($posFrom + 6) $posVia]
      :do { :set srcAddr [:tostr [:toip $srcAddr]] } on-error={ :set srcAddr "" }
      :if ($srcAddr != "" && $srcAddr != "0.0.0.0" && $srcAddr != "127.0.0.1") do={
        :if ([/ip firewall address-list find list=$trustList address=$srcAddr] = "") do={
          :if ([/ip firewall address-list find list=$banList address=$srcAddr] = "") do={
            :local attemptNum 1
            :local strikeEntry [/ip firewall address-list find list=$strikeList address=$srcAddr]
            :if ($strikeEntry != "") do={
              :set attemptNum [:tonum [/ip firewall address-list get $strikeEntry comment]]
              :set attemptNum ($attemptNum + 1)
              /ip firewall address-list remove $strikeEntry
            }
            :if ($attemptNum >= $maxAttempts) do={
              /ip firewall address-list add list=$banList address=$srcAddr timeout=$banTimeout comment="autoban"
              :log warning ("BANNED: $srcAddr")
            } else={
              /ip firewall address-list add list=$strikeList address=$srcAddr timeout=1h comment="$attemptNum"
            }
          }
        }
      }
    }
    :set lastLogIdx $logIdx
  }
}
```

### 6. Ручной запуск (опционально)

```routeros
/system script run ban-failed-logins
```

---

## Полезные команды

```routeros
# Кто забанен
/ip firewall address-list print where list="login-failed-ban"

# Счётчик попыток (1–4)
/ip firewall address-list print where list="login-strike"

# Разбанить IP
/ip firewall address-list remove [find list="login-failed-ban" address="203.0.113.50"]

# История банов в логе
/log print where topics~"script" and message~"BANNED"

# Последние атаки
/log print where topics~"critical" and message~"login failure for user"

# Статус scheduler
/system scheduler print detail where name="ban-failed-logins"

# Сброс указателя лога (при отладке)
:global lastLogIdx
:set lastLogIdx ""
```

---

## Настройка параметров

В начале скрипта:

| Переменная | По умолчанию | Смысл |
|------------|--------------|-------|
| `maxAttempts` | `5` | Попыток до бана |
| `banTimeout` | `1d` | Длительность бана (`7d`, `12h`, …) |

Timeout для `login-strike` — **1 час** (`timeout=1h` в скрипте).

---

## Рекомендации по hardening

Помимо log-based ban — сузить поверхность атаки на CHR в интернете.

### Ограничить SSH и Winbox по адресам

Разрешить управление только с доверенных сетей/IP (подставьте свои значения):

```routeros
/ip service
set ssh address=YOUR_LAN_SUBNET,YOUR_OFFICE_IP/32,YOUR_MOBILE_IP/32
set winbox address=YOUR_LAN_SUBNET,YOUR_OFFICE_IP/32,YOUR_MOBILE_IP/32
```

### Отключить неиспользуемые сервисы

Telnet, FTP, WebFig, API — лишние точки входа; на публичном CHR их лучше выключить:

```routeros
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set api disabled=yes
set api-ssl disabled=yes
```

### Отключить обнаружение соседей (MNDP/CDP)

Иначе роутер «светится» в сети — соседи видят его в Winbox/Neighbors:

```routeros
/ip neighbor discovery-settings
set discover-interface-list=none
```

### Ограничить MAC Winbox и MAC ping

Блокирует подключение к роутеру по MAC-адресу с любого интерфейса (обход IP-firewall):

```routeros
/tool mac-server
set allowed-interface-list=none
/tool mac-server mac-winbox
set allowed-interface-list=none
/tool mac-server ping
set enabled=no
```

> Если нужен Winbox по MAC с LAN — вместо `none` укажите список интерфейсов, например `LAN`, и добавьте интерфейсы в **Interface List**.

---

## Troubleshooting

| Симптом | Причина | Решение |
|---------|---------|---------|
| Списки пустые после атак | Скрипт запустился до появления записей в логе | Подождать 1–2 мин или `/system script run ban-failed-logins` |
| Новые атаки не учитываются | Scheduler выключен или скрипт с флагом `I` | `/system scheduler print detail`; проверить Source в Winbox |
| Мусорный адрес в `login-strike` | В лог попали не те строки | Фильтр `topics~"critical" and message~"login failure for user"` |
| CHR: флаг `I - INVALID` | Обрезанная вставка через терминал | Winbox или import `.rsc` |

---

---

# MikroTik CHR — log-based SSH/Winbox ban (fail2ban-like)

**RouterOS 7.x** (tested on **7.23.1 stable**)

Ban IP addresses after failed login attempts by parsing the system log — not by counting TCP connections. Successful logins do not increase the counter.

Related files in this repository:

- `mikrotik-ban-failed-logins-source.txt` — script body for Winbox
- `mikrotik-ban-failed-logins.rsc` — importable `.rsc` for terminal

---

## How it works

| Step | Behavior |
|------|----------|
| 1–4 failed logins | IP added to `login-strike` (timeout **1 hour**, comment = attempt count) |
| 5+ failed logins | IP moved to `login-failed-ban` (timeout **1 day**) |
| Firewall | Drop rule on `chain=input` for `login-failed-ban` |
| Scheduler | Script runs every **1 minute** |
| Whitelist | IPs in `mgmt_trusted` are never banned |

The script tracks the last processed log entry (`lastLogIdx`). If that entry rotates out of the memory log buffer, the script auto-resets and continues.

Log filter: `topics~"critical" and message~"login failure for user"` — real failed logins only, not script source dumps in the log.

---

## Installation

Replace placeholders with your values:

| Placeholder | Example |
|-------------|---------|
| `YOUR_LAN_SUBNET` | `10.0.0.0/24` |
| `YOUR_OFFICE_IP` | `203.0.113.10` |
| `YOUR_MOBILE_IP` | `203.0.113.20` |

### 1. Trusted IPs (whitelist)

```routeros
/ip firewall address-list
add list=mgmt_trusted address=YOUR_LAN_SUBNET comment="LAN/VPN"
add list=mgmt_trusted address=YOUR_OFFICE_IP/32 comment="management IP office"
add list=mgmt_trusted address=YOUR_MOBILE_IP/32 comment="management IP mobile/APN"
```

### 2. Drop rule for banned IPs

```routeros
/ip firewall filter
add chain=input src-address-list=login-failed-ban action=drop comment="Drop IPs banned for failed logins"
move [find comment="Drop IPs banned for failed logins"] destination=0
```

### 3. Create the script (empty source first)

```routeros
/system script add name=ban-failed-logins owner=YOUR_USER policy=read,write,test,policy,sniff,sensitive comment="ban failed logins" source=""
```

### 4. Scheduler (every 1 minute)

```routeros
/system scheduler add name=ban-failed-logins interval=1m on-event=ban-failed-logins policy=read,write,test,policy,sniff,sensitive
```

### 5. Paste script body

**Winbox:** System → Scripts → `ban-failed-logins` → **Source** → paste the script below → **OK**.

Click **Run Script** — expected: `Action Run Script OK`.

On some CHR instances the script may show flag `I` (INVALID) after terminal paste; if **Run Script** succeeds, it is usually cosmetic. Prefer Winbox or `/import` of the `.rsc` file.

### Script body

```routeros
:global lastLogIdx
:local banList "login-failed-ban"
:local strikeList "login-strike"
:local trustList "mgmt_trusted"
:local maxAttempts 5
:local banTimeout 1d
:if ([:typeof $lastLogIdx] = "nothing") do={ :set lastLogIdx "" }
:local foundLast 0
:foreach logIdx in=[/log find where topics~"critical" and message~"login failure for user"] do={
  :if ($logIdx = $lastLogIdx) do={ :set foundLast 1 }
}
:if ($lastLogIdx != "" && $foundLast = 0) do={ :set lastLogIdx "" }
:local processNew 0
:if ($lastLogIdx = "") do={ :set processNew 1 }
:foreach logIdx in=[/log find where topics~"critical" and message~"login failure for user"] do={
  :if ($processNew = 0) do={
    :if ($logIdx = $lastLogIdx) do={ :set processNew 1 }
  } else={
    :local logMsg [/log get $logIdx message]
    :local posFrom [:find $logMsg " from "]
    :local posVia [:find $logMsg " via "]
    :if ([:typeof $posFrom] != "nothing" && [:typeof $posVia] != "nothing") do={
      :local srcAddr [:pick $logMsg ($posFrom + 6) $posVia]
      :do { :set srcAddr [:tostr [:toip $srcAddr]] } on-error={ :set srcAddr "" }
      :if ($srcAddr != "" && $srcAddr != "0.0.0.0" && $srcAddr != "127.0.0.1") do={
        :if ([/ip firewall address-list find list=$trustList address=$srcAddr] = "") do={
          :if ([/ip firewall address-list find list=$banList address=$srcAddr] = "") do={
            :local attemptNum 1
            :local strikeEntry [/ip firewall address-list find list=$strikeList address=$srcAddr]
            :if ($strikeEntry != "") do={
              :set attemptNum [:tonum [/ip firewall address-list get $strikeEntry comment]]
              :set attemptNum ($attemptNum + 1)
              /ip firewall address-list remove $strikeEntry
            }
            :if ($attemptNum >= $maxAttempts) do={
              /ip firewall address-list add list=$banList address=$srcAddr timeout=$banTimeout comment="autoban"
              :log warning ("BANNED: $srcAddr")
            } else={
              /ip firewall address-list add list=$strikeList address=$srcAddr timeout=1h comment="$attemptNum"
            }
          }
        }
      }
    }
    :set lastLogIdx $logIdx
  }
}
```

### 6. Run manually (optional)

```routeros
/system script run ban-failed-logins
```

---

## Useful commands

```routeros
# Banned IPs
/ip firewall address-list print where list="login-failed-ban"

# Strike counter (1–4 attempts)
/ip firewall address-list print where list="login-strike"

# Unban one IP
/ip firewall address-list remove [find list="login-failed-ban" address="203.0.113.50"]

# Ban history in log
/log print where topics~"script" and message~"BANNED"

# Recent failed logins
/log print where topics~"critical" and message~"login failure for user"

# Scheduler status
/system scheduler print detail where name="ban-failed-logins"

# Reset log pointer (if needed after manual debugging)
:global lastLogIdx
:set lastLogIdx ""
```

---

## Tuning

Edit at the top of the script:

| Variable | Default | Meaning |
|----------|---------|---------|
| `maxAttempts` | `5` | Failed logins before ban |
| `banTimeout` | `1d` | Ban duration (`7d`, `12h`, …) |

Strike list timeout is fixed at **1 hour** in the script (`timeout=1h` on `login-strike`).

---

## Recommended hardening

In addition to log-based ban — reduce the attack surface on a public-facing CHR.

### Restrict SSH and Winbox by address

Allow management only from trusted subnets/IPs (replace placeholders):

```routeros
/ip service
set ssh address=YOUR_LAN_SUBNET,YOUR_OFFICE_IP/32,YOUR_MOBILE_IP/32
set winbox address=YOUR_LAN_SUBNET,YOUR_OFFICE_IP/32,YOUR_MOBILE_IP/32
```

### Disable unused services

Telnet, FTP, WebFig, and API are extra entry points — disable them on a public CHR:

```routeros
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set api disabled=yes
set api-ssl disabled=yes
```

### Disable neighbor discovery (MNDP/CDP)

Otherwise the router advertises itself on the network — visible in Winbox Neighbors:

```routeros
/ip neighbor discovery-settings
set discover-interface-list=none
```

### Restrict MAC Winbox and MAC ping

Prevents layer-2 access to the router from any interface (bypassing IP firewall):

```routeros
/tool mac-server
set allowed-interface-list=none
/tool mac-server mac-winbox
set allowed-interface-list=none
/tool mac-server ping
set enabled=no
```

> If you need MAC Winbox from LAN only — use an interface list (e.g. `LAN`) instead of `none` and assign interfaces under **Interface Lists**.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Lists empty after attacks | Script ran before log entries appeared | Wait 1–2 min or `/system script run ban-failed-logins` |
| New attacks not counted | Scheduler disabled or script flag `I` | `/system scheduler print detail`; verify Source in Winbox |
| Garbage address in `login-strike` | Wrong log lines matched | Filter: `topics~"critical" and message~"login failure for user"` |
| CHR shows `I - INVALID` on script | Terminal paste truncated closing `}` | Paste via Winbox or import `.rsc` |

---

## License

MIT — see `LICENSE` in the repository root (when published).
