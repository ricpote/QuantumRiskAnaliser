"""Record a reference pcap of REAL SSH key exchanges (OpenSSH >= 9.0 client and server on 127.0.0.1:2222).

  sudo python samples/extra/pcap/record_ssh.py

Sessions: OpenSSH default (sntrup761x25519 PQ hybrid), forced sntrup761x25519, classical curve25519,
legacy diffie-hellman-group14-sha1 + ssh-rsa + aes128-cbc + hmac-sha1. Authentication is expected
to fail (BatchMode, no keys): only the key exchange matters.
"""
import os
import shutil
import subprocess
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "lab-ssh.pcapng")
tmp = tempfile.mkdtemp(prefix="qt_sshd_")
for t in ("ed25519", "rsa"):
    subprocess.run(["ssh-keygen", "-q", "-t", t, "-N", "", "-f", f"{tmp}/host_{t}"] + (["-b", "2048"] if t == "rsa" else []), check=True)
cfg = f"""Port 2222
ListenAddress 127.0.0.1
HostKey {tmp}/host_ed25519
HostKey {tmp}/host_rsa
PidFile {tmp}/sshd.pid
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
KexAlgorithms +diffie-hellman-group14-sha1
HostKeyAlgorithms +ssh-rsa
Ciphers +aes128-cbc
MACs +hmac-sha1
"""
open(f"{tmp}/sshd_config", "w").write(cfg)
os.makedirs("/run/sshd", exist_ok=True)
sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", f"{tmp}/sshd_config"], stderr=subprocess.DEVNULL)
cap = subprocess.Popen([shutil.which("dumpcap") or shutil.which("tshark"), "-q", "-i", "lo", "-f", "tcp port 2222", "-w", OUT],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)
base = ["ssh", "-p", "2222", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=3", "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=/dev/null"]
runs = {
    "openssh-default (PQ sntrup761x25519)": [],
    "forced sntrup761x25519": ["-o", "KexAlgorithms=sntrup761x25519-sha512@openssh.com"],
    "classical curve25519 + rsa-sha2-512": ["-o", "KexAlgorithms=curve25519-sha256", "-o", "HostKeyAlgorithms=rsa-sha2-512"],
    "legacy group14-sha1/ssh-rsa/aes128-cbc/hmac-sha1": ["-o", "KexAlgorithms=diffie-hellman-group14-sha1", "-o", "HostKeyAlgorithms=ssh-rsa",
                                                          "-o", "Ciphers=aes128-cbc", "-o", "MACs=hmac-sha1"],
}
for name, opts in runs.items():
    r = subprocess.run(base + opts + ["-v", "qtrace@127.0.0.1", "true"], capture_output=True, text=True, timeout=15)
    kex = [l for l in r.stderr.splitlines() if "kex: algorithm:" in l or "kex: host key algorithm:" in l or "cipher:" in l]
    print(f"{name:52} {' | '.join(k.split('debug1: ')[-1] for k in kex[:3])}")
time.sleep(1.5)
cap.terminate(); cap.wait()
sshd.terminate()
shutil.rmtree(tmp, ignore_errors=True)
print("wrote", OUT, os.path.getsize(OUT), "bytes")
