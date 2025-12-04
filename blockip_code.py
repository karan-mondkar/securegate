import subprocess

def block_ip(ip):
    try:
        # Rule names
        inbound_rule = f"Block_in_{ip}"
        outbound_rule = f"Block_out_{ip}"

        # Inbound block
        cmd_in = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={inbound_rule}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ]

        # Outbound block (VERY IMPORTANT for VMs)
        cmd_out = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={outbound_rule}",
            "dir=out",
            "action=block",
            f"remoteip={ip}"
        ]

        subprocess.run(cmd_in, check=True)
        subprocess.run(cmd_out, check=True)

        print(f"[+] FULL BLOCK applied to: {ip}")

    except Exception as e:
        print(f"[!] Error blocking IP: {e}")


def unblock_ip(ip):
    try:
        inbound_rule = f"Block_in_{ip}"
        outbound_rule = f"Block_out_{ip}"

        cmd_in = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={inbound_rule}"
        ]

        cmd_out = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={outbound_rule}"
        ]

        subprocess.run(cmd_in, check=True)
        subprocess.run(cmd_out, check=True)

        print(f"[+] FULL UNBLOCK removed for: {ip}")

    except Exception as e:
        print(f"[!] Error unblocking IP: {e}")


block_ip("192.168.219.45")
