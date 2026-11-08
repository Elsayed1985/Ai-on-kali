#!/usr/bin/env python3
"""kali: مساعد أوامر عربي لـ Termux وKali NetHunter.

  kali                  اعرض ملفات المشروع
  kali <طلب عربي>       اختصار سريع، أو تحويل الطلب إلى أمر عبر Gemini
  kali root <تعديل>     عدّل البرنامج نفسه بعد موافقتك (root اسم للأمر فقط ولا يمنح صلاحيات)
  kali --self-test      اختبار داخلي
"""
import json
import os
import re
import shlex
import sys
from getpass import getpass
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
SELF_FILE = Path(__file__).resolve()
KEY_FILE = Path.home() / ".config/arabic-kali-ai/gemini_key"
MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# ===== BEGIN PROTECTED: الأمان والتنفيذ والكتابة والتحقق. لا يعدّله التعديل الذاتي =====
import difflib
import shutil
import subprocess
import time

MARK_BEGIN = "# " + "=" * 5 + " BEGIN PROTECTED"
MARK_END = "# " + "=" * 5 + " END PROTECTED"
TIMEOUT_SECONDS = 30
MAX_OUTPUT_LINES = 40
MAX_DIFF_LINES = 80
MAX_SOURCE_CHARS = 80_000
MAX_ARGS = 10
MAX_TOKEN_LEN = 200
SAFE_TOKEN = re.compile(r"[A-Za-z0-9_./~:+,@=-]+")

# الأمر: (الخيارات المسموحة، هل تُقبل مسارات كوسيطات؟)
RULES = {
    # معلومات النظام
    "pwd": (set(), False),
    "whoami": (set(), False),
    "id": (set(), False),
    "hostname": (set(), False),
    "uname": ({"-a", "-r", "-m"}, False),
    "uptime": (set(), False),
    "date": (set(), False),
    "arch": (set(), False),
    "nproc": (set(), False),
    "lscpu": (set(), False),

    # الذاكرة والتخزين
    "free": ({"-h", "-m"}, False),
    "df": ({"-h"}, True),
    "du": ({"-h", "-s", "-sh"}, True),
    "lsblk": ({"-a", "-f", "-l"}, False),
    "findmnt": (set(), False),
    "mount": (set(), False),

    # عرض معلومات الملفات ومسارات الأدوات
    "ls": ({"-l", "-a", "-h", "-la", "-lah", "-al", "-lh", "-ah"}, True),
    "stat": (set(), True),
    "file": (set(), True),
    "which": (set(), True),
    "sha256sum": (set(), True),
    "wc": ({"-l", "-w", "-c"}, True),

    # العمليات والشبكة: استعلامات محدودة
    "ps": ({"-A", "-e", "-f", "-ef"}, False),
    "ip": (set(), False),

    # أدوات Termux إن كانت مثبتة
    "termux-battery-status": (set(), False),
    "termux-wifi-connectioninfo": (set(), False),
}
IP_SUBCOMMANDS = {("addr", "show"), ("route", "show"), ("link", "show")}

# أدوات خطرة ممنوعة خارج هذا القسم في أي تعديل ذاتي (فحص بالكلمات، وليس جداراً كاملاً)
FORBIDDEN_OUTSIDE = re.compile(
    r"\b(subprocess|shutil|socket|pty|ctypes|importlib|builtins|__import__|"
    r"rmtree|write_text|write_bytes|getattr|globals)\b"
    r"|\bos\.(system|remove|unlink|rmdir|replace|rename|chmod|chown|popen|kill|fork)\b"
    r"|\bfrom\s+(os|subprocess|shutil|socket)\s+import\b"
    r"|\b(eval|exec|compile)\s*\("
    r"|\bopen\s*\("
)


def validate(cmd):
    if not isinstance(cmd, list) or not 1 <= len(cmd) <= MAX_ARGS:
        return False
    if not all(isinstance(x, str) and 0 < len(x) <= MAX_TOKEN_LEN and SAFE_TOKEN.fullmatch(x)
               for x in cmd):
        return False
    name, args = cmd[0], cmd[1:]
    if name not in RULES:
        return False
    if name == "ip":
        return tuple(args) in IP_SUBCOMMANDS
    flags, paths_allowed = RULES[name]
    for arg in args:
        if arg.startswith("-"):
            if arg not in flags:
                return False
        elif not paths_allowed:
            return False
    return True


def trim(text, limit=MAX_OUTPUT_LINES):
    lines = text.rstrip().splitlines()
    if len(lines) <= limit:
        return "\n".join(lines)
    hidden = len(lines) - limit
    return "\n".join(lines[:limit]) + f"\n... (تم إخفاء {hidden} سطر)"


def confirm(question):
    try:
        return input(question).strip().lower() in ("y", "yes", "نعم")
    except EOFError:
        return False


def execute(cmd, ask=True):
    """الطريقة الوحيدة لتشغيل أي أمر. لا تمر إلا أوامر القائمة المسموحة."""
    if not validate(cmd):
        print("تم رفض الأمر لأنه غير مسموح.")
        return False
    if not shutil.which(cmd[0]):
        print(f"الأداة '{cmd[0]}' غير مثبتة في هذه البيئة.")
        return False
    if ask:
        print("\nالأمر:", shlex.join(cmd))
        if not confirm("هل توافق على التنفيذ؟ (y/n): "):
            print("تم الإلغاء.")
            return False
    # shell=False لا يوسّع "~"، فنوسّعه هنا بعد التحقق من الأمر
    args = [os.path.expanduser(x) if x.startswith("~") else x for x in cmd]
    try:
        result = subprocess.run(args, shell=False, capture_output=True,
                                text=True, timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        print("انتهت مهلة تنفيذ الأمر.")
        return False
    print(trim(result.stdout) or "لا توجد نتائج.")
    if result.stderr.strip():
        print("رسائل النظام:", trim(result.stderr))
    print("Exit code:", result.returncode)
    return result.returncode == 0


def save_key(key):
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)


def protected_span(src):
    if src.count(MARK_BEGIN) != 1 or src.count(MARK_END) != 1:
        return None
    start = src.index(MARK_BEGIN)
    end_pos = src.index(MARK_END)
    if end_pos < start:
        return None
    line_end = src.find("\n", end_pos)
    return start, (len(src) if line_end == -1 else line_end + 1)


def verify_candidate(old_src, new_src):
    if len(new_src) > MAX_SOURCE_CHARS:
        return False, "الملف الجديد كبير جداً."
    old_span = protected_span(old_src)
    new_span = protected_span(new_src)
    if old_span is None or new_span is None:
        return False, "علامات القسم المحمي مفقودة أو مكررة."
    if old_src[old_span[0]:old_span[1]] != new_src[new_span[0]:new_span[1]]:
        return False, "التعديل يمس القسم المحمي (الأمان)، وهذا ممنوع."
    outside = new_src[:new_span[0]] + new_src[new_span[1]:]
    match = FORBIDDEN_OUTSIDE.search(outside)
    if match:
        return False, f"عملية ممنوعة خارج القسم المحمي: {match.group(0)}"
    try:
        compile(new_src, "kali.py", "exec")
    except SyntaxError as error:
        return False, f"خطأ في بناء الجملة: {error}"
    return True, ""


def change_summary(old_src, new_src):
    """يأخذ آخر سطر CHANGE جديد فعلاً، لا السطر القديم من تعديل سابق."""
    old_lines = set(old_src.splitlines())
    added = [ln[len("# CHANGE:"):].strip() for ln in new_src.splitlines()
             if ln.startswith("# CHANGE:") and ln not in old_lines]
    return added[-1] if added else "بدون ملخص"


def strip_fences(text):
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z]*\s*\n", "", text)
    text = re.sub(r"\n?```$", "", text)
    return text.rstrip() + "\n"


def new_backup_name():
    stamp = time.strftime("%Y%m%d-%H%M%S")
    n = 0
    while True:
        suffix = f"-{n}" if n else ""
        path = SELF_FILE.with_name(f"{SELF_FILE.name}.{stamp}{suffix}.bak")
        if not path.exists():
            return path
        n += 1


def review_and_apply(old_src, new_src):
    """الحارس الأخير: يتحقق، يعرض الفرق، يطلب موافقتك، يختبر النسخة، ثم يطبّق."""
    ok, reason = verify_candidate(old_src, new_src)
    if not ok:
        return False, "رُفض التعديل: " + reason

    diff = list(difflib.unified_diff(old_src.splitlines(), new_src.splitlines(),
                                     lineterm="", n=0))
    added = sum(1 for ln in diff if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff if ln.startswith("-") and not ln.startswith("---"))
    print(f"\nالتغيير المقترح: {change_summary(old_src, new_src)}")
    print(f"+{added} سطر  -{removed} سطر")
    print(trim("\n".join(diff), MAX_DIFF_LINES))
    if not confirm("طبّق التعديل؟ (y/n): "):
        return False, "تم الإلغاء، لم يتغيّر أي شيء."

    candidate = SELF_FILE.with_name(SELF_FILE.name + ".new")
    candidate.write_text(new_src, encoding="utf-8")
    try:
        result = subprocess.run([sys.executable, str(candidate), "--self-test"],
                                capture_output=True, text=True, timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        candidate.unlink(missing_ok=True)
        return False, "انتهت مهلة اختبار النسخة الجديدة، لم يتغيّر الملف."
    if result.returncode != 0:
        candidate.unlink(missing_ok=True)
        return False, "فشل الاختبار الذاتي، لم يتغيّر الملف.\n" + trim(result.stdout + result.stderr)

    backup = new_backup_name()
    shutil.copy2(SELF_FILE, backup)
    os.replace(candidate, SELF_FILE)
    return True, f"تم التطبيق. النسخة السابقة محفوظة في {backup.name}. ستعمل من التشغيل القادم."


def self_test():
    for cmd in [["ls", "-lah"], ["ls", "-lah", "/data/data/com.termux/files/home/arabic-kali-ai"],
                ["df", "-h"], ["du", "-sh", "~"], ["date"], ["ip", "addr", "show"],
                ["termux-battery-status"]]:
        assert validate(cmd), f"كان يجب قبول: {cmd}"

    for cmd in [["hostname"], ["lscpu"], ["nproc"], ["lsblk", "-f"],
                ["findmnt"], ["mount"], ["ps", "-ef"],
                ["stat", "."], ["file", "."], ["which", "python"],
                ["sha256sum", "kali.py"], ["wc", "-l", "kali.py"]]:
        assert validate(cmd), f"كان يجب قبول: {cmd}"

    for cmd in [["rm", "-rf", "/"], ["bash", "-c", "id"], ["ls", ";", "rm"],
                ["date", "-s", "2020-01-01"], ["ip", "link", "set", "wlan0", "up"],
                ["ls", "--color=always"], ["uname", "-a;rm"], [],
                ["ps", "aux"], ["lsblk", "-o", "NAME"],
                ["mount", "-o", "remount"], ["lscpu", ";", "rm"],
                ["nmap", "example.com"]]:
        assert not validate(cmd), f"كان يجب رفض: {cmd}"

    sample = "x = 1\n" + MARK_BEGIN + "\nSECRET = 1\n" + MARK_END + "\ny = 2\n"
    assert verify_candidate(sample, sample)[0], "التحقق يرفض نسخة سليمة"
    assert not verify_candidate(sample, sample.replace("SECRET = 1", "SECRET = 2"))[0], \
        "لم يُمنع تغيير القسم المحمي"
    assert not verify_candidate(sample, sample + "import subprocess\n")[0], \
        "لم تُمنع أداة خطرة خارج القسم المحمي"

    # الملف نفسه يجب أن يجتاز حارسه، وإلا فلن يُقبل أي تعديل لاحق
    me = SELF_FILE.read_text(encoding="utf-8")
    ok, why = verify_candidate(me, me)
    assert ok, f"الملف نفسه لا يجتاز حارسه: {why}"

    assert strip_fences("```python\nx = 1\n```") == "x = 1\n", "فشل تنظيف الغلاف"
    assert strip_fences("x = 1") == "x = 1\n", "فشل تنظيف نص بلا غلاف"
# ===== END PROTECTED =====


# ===== الخصائص: يمكن للتعديل الذاتي تغييرها، والقسم المحمي يبقى ثابتاً =====

SHORTCUTS = {
    "بطارية": ["termux-battery-status"],
    "واي فاي": ["termux-wifi-connectioninfo"],
    "شبكة": ["ip", "addr", "show"],
    "تخزين": ["df", "-h"],
    "ذاكرة": ["free", "-h"],
    "مكان": ["pwd"],
    "وقت": ["date"],
    "نظام": ["uname", "-a"],
    "مستخدم": ["whoami"],
}

COMMAND_SYSTEM = """
أنت مساعد أوامر عربي متخصص في Kali NetHunter وTermux.
حوّل طلب المستخدم إلى أمر واحد فقط، واختره من هذه القائمة حصراً: ALLOWED_LIST
أرجع JSON فقط بهذا الشكل:
{"explanation": "شرح الأمر بالعربية", "command": ["ls", "-lah"]}
القواعد:
1. أوامر قراءة واستعلام فقط.
2. لا تستخدم shell أو sudo أو pipes أو خيارات غير مذكورة في القائمة.
3. لا تقترح حذف أو تعديل ملفات النظام، ولا اختراق أجهزة أو شبكات.
4. أمر واحد فقط بلا سلاسل.
5. إذا لم يمكن تحويل الطلب إلى أمر من القائمة، أرجع "command" فارغة [].
6. لا تخترع نتائج تنفيذ.
"""

EDIT_SYSTEM = """
أنت مهندس برمجيات. ستصلك رسالة تحتوي طلب تعديل، وملف Python كامل.
أرجع الملف الكامل بعد التعديل فقط، بلا شرح خارجه، وبلا Markdown أو علامات ```.
أضف سطر تعليق بهذا الشكل خارج القسم المحمي: # CHANGE: ملخص قصير بالعربية لما تغيّر
القواعد الصارمة:
1. انسخ القسم المحصور بين سطر BEGIN PROTECTED وسطر END PROTECTED حرفياً دون أي تغيير.
2. لا تضف أي أمر تشغيل خارجي، أو وصول للشبكة، أو كتابة مباشرة للملفات، خارج القسم المحمي.
3. حافظ على التوافق مع Python 3 وTermux، ولا تضف مكتبات جديدة.
4. غيّر ما يطلبه المستخدم فقط، واحفظ بقية الوظائف كما هي.
5. نفّذ الطلب كاملاً، ولا تحذف خاصية إلا إذا طُلب ذلك صراحة.
"""


def get_key():
    if not KEY_FILE.exists():
        key = getpass("أدخل Gemini API Key: ").strip()
        if not key:
            raise RuntimeError("المفتاح فارغ.")
        save_key(key)
    key = KEY_FILE.read_text().strip()
    if not key:
        raise RuntimeError("مفتاح Gemini غير صالح.")
    return key


def ask_gemini(system, prompt, json_mode, max_tokens):
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        raise RuntimeError("مكتبة google-genai غير مثبتة. نفّذ: pip install google-genai")
    client = genai.Client(api_key=get_key())
    response = client.models.generate_content(
        model=MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=system,
            response_mime_type="application/json" if json_mode else "text/plain",
            temperature=0.1,
            max_output_tokens=max_tokens,
        ),
    )
    if not response.text:
        raise RuntimeError("لم يرجع Gemini استجابة.")
    return response.text


def feature_self_edit(text):
    parts = text.split(maxsplit=1)
    if not parts or parts[0].lower() not in ("root", "روت"):
        return False
    request = parts[1].strip() if len(parts) > 1 else ""
    if not request:
        print("اكتب التعديل المطلوب، مثال: kali root غيّر الواجهة إلى الإنجليزية")
        return True
    old_src = SELF_FILE.read_text(encoding="utf-8")
    print("أطلب التعديل من Gemini...")
    try:
        # نماذج Gemini تحسب أفكارها داخل الحد، لذلك نترك حداً واسعاً للملف كاملاً
        raw = ask_gemini(EDIT_SYSTEM, f"طلب التعديل: {request}\n\nالملف الحالي:\n{old_src}",
                         False, 32000)
    except Exception as error:
        print("تعذّر التعديل:", error)
        return True
    ok, message = review_and_apply(old_src, strip_fences(raw))
    print(("✔ " if ok else "✘ ") + message)
    return True


def feature_files(text):
    if text and "ملف" not in text:
        return False
    print("ملفات المشروع:", PROJECT_DIR)
    os.chdir(PROJECT_DIR)   # ls بلا مسار حتى لا يُرفض مسار فيه مسافة
    execute(["ls", "-lah"], ask=False)
    return True


def feature_shortcuts(text):
    for keyword, cmd in SHORTCUTS.items():
        if keyword in text:
            execute(cmd)
            return True
    return False


def feature_ai_command(text):
    if not text:
        print("الاستخدام: kali <طلبك بالعربية>")
        return True
    system = COMMAND_SYSTEM.replace("ALLOWED_LIST", ", ".join(sorted(RULES)))
    try:
        data = json.loads(ask_gemini(system, text, True, 4000))
    except Exception as error:
        print("تعذّر الحصول على رد من Gemini:", error)
        return True
    if not isinstance(data, dict):
        print("شكل الرد غير صالح.")
        return True
    print("\nشرح Gemini:", data.get("explanation", ""))
    command = data.get("command") or []
    if isinstance(command, str):
        try:
            command = shlex.split(command)
        except ValueError:
            command = []
    if not command:
        print("لم يقترح Gemini أمراً آمناً لهذا الطلب.")
        return True
    execute(command)
    return True


FEATURES = [feature_self_edit, feature_files, feature_shortcuts, feature_ai_command]


def main():
    if sys.argv[1:] == ["--self-test"]:
        try:
            self_test()
        except AssertionError as error:
            print("✘ فشل الاختبار:", error)
            sys.exit(1)
        print("✔ كل الاختبارات نجحت")
        return
    text = " ".join(sys.argv[1:]).strip()
    if len(text) > 1000:
        print("الطلب طويل جداً.")
        return
    try:
        for feature in FEATURES:
            if feature(text):
                return
        print("لم أتمكن من معالجة الطلب.")
    except KeyboardInterrupt:
        print("\nتم الإيقاف.")
    except Exception as error:
        print("حدث خطأ:", error)


if __name__ == "__main__":
    main()