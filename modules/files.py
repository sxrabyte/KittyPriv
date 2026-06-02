import subprocess
from dataclasses import dataclass

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

def enumerate_pe() -> Finding:
    findings = []

    findings.append(Finding(
        label = "World writable files",
        output = "find / -writable -type f 2>/dev/null | grep -v proc",
        highlight = True
    ))

    findings.append(Finding(
        label = "World writable directories",
        output = "find / -writable -type d 2>/dev/null",
        highlight = False
    ))

    findings.append(Finding(
        label = "Path hijacking",
        output = "echo $PATH",
        highlight = False
    ))

    findings.append(Finding(
        label = "sensitive config writability",
        output = "ls -la /etc/passwd /etc/shadow /etc/sudoers",
        highlight = True
    ))

    return findings