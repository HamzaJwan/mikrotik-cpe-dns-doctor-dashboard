"""
core/mikrotik_telnet.py

عميل Telnet بسيط للتعامل مع MikroTik RouterOS باستخدام telnetlib (Python 3.12).

الفكرة:
- connect()  : فتح اتصال + Login + انتظار الـ prompt + تعطيل الـ pager.
- run_command(): تنفيذ أمر وإرجاع الـ Output بدون سطر الأمر وسطر الـ prompt.
- run_commands(): تنفيذ قائمة أوامر متتابعة.
- reboot()   : تنفيذ /system reboot (مع تأكيد y).
- close()    : إرسال /quit وإغلاق الاتصال.

تم تصميم الكود ليعمل مع Banner مثل:

  MMM      MMM       KKK ...
  MikroTik RouterOS 6.48.5 ...

[admin@WNW100045] >

ثم الأوامر…
"""

import telnetlib
import time
import re
import logging
from typing import Optional, List


class MikroTikTelnetClient:
    # Regex للتعرف على سطر الـ prompt
    PROMPT_LINE_RE = re.compile(
        r"""^(
                \[[^@\]]+@[^@\]]+\]\s*[>#]?   # [admin@WNW100045] >
             |
                [>#]                         # > أو #
            )\s*$
        """,
        re.VERBOSE,
    )

    # إزالة أكواد ANSI (الألوان)
    ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]", re.MULTILINE)

    def __init__(
        self,
        ip: str,
        port: int = 23,
        username: str = "admin",
        password: str = "",
        timeout: int = 10,
        encoding: str = "utf-8",
    ):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.encoding = encoding

        self.tn: Optional[telnetlib.Telnet] = None
        self.logger = logging.getLogger(self.__class__.__name__)

    # ----------------- Helpers -----------------

    def _decode(self, data: bytes) -> str:
        return data.decode(self.encoding, errors="ignore")

    def _strip_ansi(self, text: str) -> str:
        return self.ANSI_ESCAPE_RE.sub("", text)

    def _is_prompt_line(self, line: str) -> bool:
        return bool(self.PROMPT_LINE_RE.match(line.strip()))

    def _read_line(self, timeout: Optional[float] = None) -> str:
        """قراءة سطر واحد حتى \\n من Telnet."""
        if self.tn is None:
            raise RuntimeError("Telnet connection is not open.")

        data = self.tn.read_until(b"\n", timeout=timeout)
        if not data:
            return ""
        line = self._decode(data).rstrip("\r\n")
        line = self._strip_ansi(line)
        return line

    def _read_until_prompt(self) -> str:
        """
        قراءة سطور متتالية حتى نصل إلى سطر الـ prompt.
        تُستخدم:
        - بعد الأوامر في run_command
        """
        if self.tn is None:
            raise RuntimeError("Telnet connection is not open.")

        lines = []
        start = time.time()

        while True:
            remaining = self.timeout - (time.time() - start)
            if remaining <= 0:
                break

            line = self._read_line(timeout=remaining)
            if line == "" and not lines:
                # تجاهل الفراغات في البداية
                continue

            if line != "":
                lines.append(line)

            if self._is_prompt_line(line):
                break

        return "\n".join(lines).strip("\n")

    def _flush_buffer(self) -> None:
        """مسح أي بيانات متبقية في الـ buffer (للاحتياط)."""
        if not self.tn:
            return
        time.sleep(0.1)
        try:
            _ = self.tn.read_very_eager()
        except Exception:
            pass

    # ----------------- Connect / Login -----------------

    def connect(self) -> None:
        """
        فتح اتصال Telnet + Login + انتظار الـ prompt + تعطيل الـ pager.
        هنا في الـ login لا نعتمد على _read_until_prompt، بل نقرأ حتى "> ".
        """
        self.logger.info("Connecting to %s:%s ...", self.ip, self.port)
        self.tn = telnetlib.Telnet(self.ip, self.port, timeout=self.timeout)

        # Login:
        self.logger.debug("Waiting for 'Login:' ...")
        self.tn.read_until(b"Login:", timeout=self.timeout)
        self.tn.write(self.username.encode(self.encoding) + b"\r\n")

        self.logger.debug("Waiting for 'Password:' ...")
        self.tn.read_until(b"Password:", timeout=self.timeout)
        self.tn.write(self.password.encode(self.encoding) + b"\r\n")

        # بعد الـ Password، نقرأ حتى ظهور الـ prompt الأساسي ">"
        # (مثلاً: [admin@WNW100045] >)
        self.logger.debug("Waiting for RouterOS prompt '> ' ...")
        data = self.tn.read_until(b"> ", timeout=self.timeout)
        banner_text = self._strip_ansi(self._decode(data))
        self.logger.debug("Login banner+prompt raw:\n%s", banner_text)

        if b"Login failed" in data:
            raise RuntimeError("Login failed (RouterOS reported 'Login failed').")

        self.logger.info("Login successful (RouterOS prompt reached).")
        self._flush_buffer()

        # تعطيل الـ pager (حتى لا يكون هناك More)
        try:
            self.logger.debug("Disabling pager with /terminal set pager=never")
            self.run_command("/terminal set pager=never")
        except Exception as e:
            self.logger.warning("Could not disable pager: %s", e)

    # ----------------- Run Command(s) -----------------

    def run_command(self, command: str) -> str:
        """
        تنفيذ أمر وإرجاع الـ output بين سطر الأمر وسطر الـ prompt.
        """
        if self.tn is None:
            raise RuntimeError("Telnet connection is not open.")

        self.logger.info("Running command: %s", command)

        self._flush_buffer()

        # إرسال الأمر
        self.tn.write(command.encode(self.encoding) + b"\r\n")

        full_text = self._read_until_prompt()
        if not full_text:
            return ""

        lines = full_text.split("\n")

        # إزالة سطر الـ prompt من النهاية
        if lines and self._is_prompt_line(lines[-1]):
            lines = lines[:-1]

        # إزالة سطر الأمر من البداية إن وجد
        if lines and command.strip() in lines[0]:
            lines = lines[1:]

        output = "\n".join(lines).strip("\n")
        self.logger.debug(
            "Output for command '%s' (%d chars)", command, len(output)
        )
        return output

    def run_commands(self, commands: List[str]) -> None:
        """
        تنفيذ قائمة أوامر متتابعة بدون الحاجة لاسترجاع الـ output لكل واحد.
        مفيدة للفِكس وتحديث الإعدادات.
        """
        for cmd in commands:
            if not cmd:
                continue
            self.logger.info("Running fix command: %s", cmd)
            try:
                _ = self.run_command(cmd)
            except Exception as e:
                self.logger.error("Error while running command '%s': %s", cmd, e)

    # ----------------- Reboot -----------------

    def reboot(self, confirm: bool = True) -> None:
        """
        تنفيذ /system reboot (مع إرسال y للتأكيد).
        بعد هذا الأمر من المتوقع أن ينقطع الاتصال.
        """
        if self.tn is None:
            raise RuntimeError("Telnet connection is not open.")

        self.logger.info("Sending /system reboot ...")
        try:
            self.tn.write(b"/system reboot\r\n")
            time.sleep(0.5)
            if confirm:
                # RouterOS عادة يسأل: Reboot, yes? [y/N]:
                self.logger.debug("Confirming reboot with 'y'")
                self.tn.write(b"y\r\n")
        except Exception as e:
            self.logger.error("Error while sending reboot: %s", e)

        # ننتظر شوية ثم نغلق الـ socket محلياً
        time.sleep(1.0)
        try:
            self.tn.close()
        finally:
            self.tn = None

    # ----------------- Close -----------------

    def close(self) -> None:
        if not self.tn:
            return
        try:
            try:
                self.tn.write(b"/quit\r\n")
                time.sleep(0.2)
            except Exception:
                pass
            self.tn.close()
        finally:
            self.tn = None
