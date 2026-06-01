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

#Enumerating privilege escalation vectors
def enumerate_pe() -> list[Finding]:
    findings = []

    findings.append(Finding(
        label="SUID binaries",
        output=run_command("find / -perm -4000 -type f 2>/dev/null"),
        highlight=True
    ))

    findings.append(Finding(
        label="SGID binaries",
        output=run_command("find / -perm -2000 -type f 2>/dev/null"),
        highlight=False
    ))

    findings.append(Finding(
        label="binaries with linux capabilities",
        output=run_command("getcap -r / 2>/dev/null"),
        highlight=False
    ))

    return findings

