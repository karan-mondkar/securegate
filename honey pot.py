# minimal_honeypot_divert.py
import os
import shlex
import subprocess
import threading
import time

# ---------- STATIC CONFIG ----------
HONEYPOT_IP = "192.168.164.136"   # change to your honeypot IP
DURATION_SECONDS = 60             # auto-remove after 60 seconds (1 minute)
# -----------------------------------

# track timers so repeated calls reset the countdown
_timers = {}   # attacker_ip -> threading.Timer
_lock = threading.Lock()

def _run(cmd):
    """Run shell command (best-effort raises on failure)."""
    subprocess.check_call(shlex.split(cmd))

def _add_rules(attacker_ip):
    # enable forwarding (best-effort)
    try:
        _run("sysctl -w net.ipv4.ip_forward=1")
    except Exception:
        pass
    # add DNAT for all traffic from attacker -> honeypot (preserve ports)
    _run(f"iptables -t nat -A PREROUTING -s {attacker_ip} -j DNAT --to-destination {HONEYPOT_IP}")
    # allow forwarding attacker -> honeypot
    _run(f"iptables -A FORWARD -s {attacker_ip} -d {HONEYPOT_IP} -j ACCEPT")

def _del_rules(attacker_ip):
    # best-effort remove (ignore failures)
    try:
        _run(f"iptables -t nat -D PREROUTING -s {attacker_ip} -j DNAT --to-destination {HONEYPOT_IP}")
    except Exception:
        pass
    try:
        _run(f"iptables -D FORWARD -s {attacker_ip} -d {HONEYPOT_IP} -j ACCEPT")
    except Exception:
        pass

def remove_divert(attacker_ip):
    """
    Immediately remove diversion for attacker_ip (remove iptables rules).
    Safe to call even if no rules exist.
    """
    if os.geteuid() != 0:
        return {"status": "error", "error": "require root privileges"}
    with _lock:
        # cancel timer if present
        t = _timers.pop(attacker_ip, None)
        if t:
            try:
                t.cancel()
            except Exception:
                pass
    _del_rules(attacker_ip)
    return {"status": "ok", "attacker": attacker_ip}

def divert(attacker_ip):
    """
    Divert all traffic from attacker_ip to HONEYPOT_IP for DURATION_SECONDS.
    If already diverted, reset the timer to DURATION_SECONDS.
    Returns status dict.
    """
    if os.geteuid() != 0:
        return {"status": "error", "error": "require root privileges"}
    # add rules if not already present (we'll try add; duplicates may create multiple rules,
    # but the timer/reset behavior below will attempt to remove one set)
    try:
        _add_rules(attacker_ip)
    except subprocess.CalledProcessError as e:
        return {"status": "error", "error": f"iptables add failed: {e}"}

    # schedule removal after DURATION_SECONDS
    def _auto_remove():
        try:
            _del_rules(attacker_ip)
        finally:
            with _lock:
                _timers.pop(attacker_ip, None)

    with _lock:
        # cancel existing timer and set a new one (reset countdown)
        old = _timers.get(attacker_ip)
        if old:
            try:
                old.cancel()
            except Exception:
                pass
        t = threading.Timer(DURATION_SECONDS, _auto_remove)
        t.daemon = True
        t.start()
        _timers[attacker_ip] = t

    expires_at = int(time.time()) + DURATION_SECONDS
    return {"status": "ok", "attacker": attacker_ip, "honeypot": HONEYPOT_IP, "expires_at": expires_at}

print(divert(" 192.168.164.86"))