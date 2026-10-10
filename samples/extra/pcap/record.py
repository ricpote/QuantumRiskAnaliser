"""Record reference pcaps of REAL handshakes against the local TLS lab.

  (terminal 1)  make lab
  (terminal 2)  sudo python samples/extra/pcap/record.py      # needs tshark/dumpcap capture rights on loopback

Writes samples/extra/pcap/lab-handshakes.pcapng containing:
  * Go 1.24 client <-> PQ server: hybrid X25519MLKEM768 (key_share 1216/1120 B)
  * Go client offering PQ <-> classical server: PQ offered but NOT negotiated
  * classical-only client <-> PQ server
  * TLS 1.2 ECDHE and TLS 1.2 RSA key transport with certificates in clear (RSA-2048 SHA-1 expired)
  * TLS 1.0 + 3DES
  * HelloRetryRequest (client sends only an X25519 share to a PQ-only server)
  * SMTP STARTTLS on a NON-standard port (2525) and Postgres SSLRequest on 5433
"""
import os
import shutil
import smtplib
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, ROOT)
OUT = os.path.join(HERE, "lab-handshakes.pcapng")
PORTS = [8443, 8444, 8445, 8446, 8447, 2525, 5433]

flt = " or ".join(f"tcp port {p}" for p in PORTS)
cap = subprocess.Popen([shutil.which("dumpcap") or shutil.which("tshark"), "-q", "-i", "lo", "-f", flt, "-w", OUT],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
time.sleep(1.5)
lab = os.path.join(ROOT, "samples", "extra", "tls-lab")
handshakes = os.path.join(lab, "cmd", "handshakes")
print(subprocess.run([shutil.which("go"), "run", "."], cwd=handshakes, capture_output=True, text=True).stdout)

# HelloRetryRequest: offer X25519MLKEM768 + x25519 but send a key share ONLY for x25519 to the PQ-only server
from quantumtrace.ingest import probe as P
r = P.handshake(None, 8447, ip="127.0.0.1", versions=(0x0304,), groups=[0x11EC, 0x001D], shares=[P.KeyShare(0x001D)])
print("HRR to pq-only:", r["sh"] and r["sh"]["hrr"], "group", r["sh"] and hex(r["sh"].get("group", 0)))
# Postgres SSLRequest + full hybrid handshake (decrypted up to CertificateVerify by our client)
r = P.handshake(None, 5433, ip="127.0.0.1", starttls="postgres", groups=P.CHROME_GROUPS, shares=[P.KeyShare(0x11EC), P.KeyShare(0x001D)], decrypt=True)
print("postgres:", r["ok"], r["sh"] and hex(r["sh"].get("group", 0)), "CertificateVerify", r["cert_verify"] and hex(r["cert_verify"]))
# SMTP STARTTLS on port 2525 with the system OpenSSL client (classical)
ctx = ssl.create_default_context()
ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
s = smtplib.SMTP("127.0.0.1", 2525, timeout=5)
s.ehlo("client.lab")
s.starttls(context=ctx)
print("smtp starttls:", s.sock.version(), s.sock.cipher()[0])
s.close()

time.sleep(1.5)
cap.terminate()
cap.wait()
print("wrote", OUT, os.path.getsize(OUT), "bytes")
