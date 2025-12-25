# MikroTik CPE DNS Doctor Dashboard (MikroTikDNSAudit3)

لوحة تحكم + أدوات CLI لتدقيق وإصلاح إعدادات أجهزة MikroTik CPE عند المشتركين بشكل جماعي.
تركّز المرحلة الحالية على DNS/DHCP (وقابل للتوسع لأي Rule مستقبلية).

## Features (Stage 1 → Stage 4)
- **Stage 1: Read-only Dashboard**
  - ملخص آخر 24 ساعة (OK / Failed / Login Failed / Fix Applied / Rebooted)
  - فلترة حسب City/Status/Date/Search
- **Stage 2: Rules (CRUD)**
  - قواعد ديناميكية من قاعدة البيانات:
    - `check_command` + `warning_regex` + `fix_command`
  - تفعيل/تعطيل Rule
- **Stage 3: Run Control**
  - تشغيل `multi_cpe.py` من الويب (audit / fix / fix+reboot)
  - Targets من Radius (DMA) أو ملف input
  - Threads + Timeout + Batch Size + Progress Interval
  - Pause/Resume/Stop/Kill
- **Stage 4: Reports**
  - تقارير مبنية على نتائج التنفيذ المخزنة في MySQL
  - تصفية + Pagination + Export CSV (حسب الواجهة الحالية)

---

## Project Structure (High Level)
- `main.py` : تشغيل جهاز واحد (Single CPE)
- `multi_cpe.py` : تشغيل جماعي متعدد (Multi CPE) + Sessions
- `core/`
  - `mikrotik_telnet.py` : Telnet client لتنفيذ أوامر RouterOS
  - `parser.py` : Parsing لمخرجات RouterOS
  - `rules.py` : Rule Engine (check/warn/fix)
  - `radius_db.py` : Targets من DMA Radius DB
  - `db_manager.py` : تخزين النتائج في MySQL (sessions/logs/inventory)
- `db/schema.sql` : سكيمة قاعدة البيانات
- `web/`
  - `api.py` : FastAPI + Jinja2 UI
  - `reports_db.py` : Queries للتقارير
  - `settings.py` : إعدادات + ENV
- `ui/` : templates/static للواجهة

---

## Database Schema (MySQL)
السكيمة في: `db/schema.sql` وتشمل:
- `scan_sessions` : جلسات التشغيل (mode/city/status/meta_json)
- `rules` : قواعد الفحص والإصلاح (warning_regex + fix_command)
- `cpe_inventory` : آخر حالة لكل PPPoE user + آخر IP + summary_json/warnings_json
- `logs` : سجل نتائج كل IP داخل جلسة (status/login/warnings/raw output)

---

## Configuration (Environment Variables)

### App DB (Project DB)
يتم استخدامها في `web/settings.py` و `core/db_manager.py`:

- `DB_HOST` (default: 127.0.0.1)
- `DB_PORT` (default: 3307)
- `DB_USER` (default: root)
- `DB_PASSWORD`
- `DB_NAME` (default: cpe_doctor / حسب الإعداد)
- `SESSION_SECRET` (جلسات الويب)
- `DIAG_MODE` (اختياري)

### Radius DB (DMA)
تُستخدم في `core/radius_db.py`:
- `RADIUS_DB_HOST`
- `RADIUS_DB_PORT`
- `RADIUS_DB_USER`
- `RADIUS_DB_PASSWORD`
- `RADIUS_DB_NAME`
- `RADIUS_DB_CHARSET` (اختياري)

> ملاحظة: لا ترفع كلمات المرور إلى GitHub. استخدم `.env` أو متغيرات نظام التشغيل.

---

## Setup (Windows / Linux)

### 1) Create Virtualenv
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux:
source venv/bin/activate
