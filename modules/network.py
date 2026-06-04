import subprocess
from dataclasses import dataclass

from pygments import highlight


@dataclass
class Finding:
    label: str
    output: str
    highlight: bool

#To run system commands using python
def run_command(cmd: str) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as e:
        return f"Error: {e}"



def enumerate_pe() -> list[Finding]:
    findings = []

    findings.append(Finding(
        label = "Processes",
        output = run_command("ps aux"),
        highlight = False,
    ))

    findings.append(Finding(
        label = "Process tree with parents",
        output = run_command("ps -ef --forest"),
        highlight = False
    ))

    findings.append(Finding(
        label = "Listening TCP Ports",
        output = run_command("ss -tlnp"),
        highlight = True
    ))

    findings.append(Finding(
        label = "Listening UDP Ports",
        output = run_command("ss -ulnp"),
        highlight = False
    ))

    findings.append(Finding(
        label = "Network Interfaces & IPs",
        output = run_command("ip a / ifconfig"),
        highlight = False
    ))

    findings.append(Finding(
        label = "local hostname mappings",
        output = run_command("cat /etc/hosts"),
        highlight = False
    ))

    findings.append(Finding(
        label = "ARP table",
        output = run_command("arp -a"),
        highlight = False
    ))

    return findings