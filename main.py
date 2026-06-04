import modules.users as users
import modules.suid as suid
import modules.network as network
import modules.files as files

RESET = "\033[0m"
ROSE_PINK = "\033[38;2;255;105;180m"
BABY_BLUE = "\033[38;2;137;207;240m"


def print_findings(findings):
    for finding in findings:
        marker = f"{ROSE_PINK}[!]{RESET}" if finding.highlight else f"{BABY_BLUE}[-]{RESET}"
        print(f"\n{marker} {finding.label}")
        print(finding.output)

def main():
    print(f"{ROSE_PINK}[+] CatScan starting...{RESET} \n")

    modules = [users, suid, network, files]

    for module in modules:
        findings = module.enumerate_pe()
        print_findings(findings)

if __name__ == "__main__":
    main()
