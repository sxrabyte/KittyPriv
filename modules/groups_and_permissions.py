import subprocess
from dataclasses import dataclass
from idlelib.grep import findfiles


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
        label="current user",
        output=run_command("id"),
        highlight=False
    ))

    findings.append(Finding(
        label="whoami",
        output=run_command("whoami"),
        highlight=False
    ))

    findings.append(Finding(
        label="Sudo Permissions",
        output=run_command("sudo -l"),
        highlight=True
    ))

    return findings