import re
import subprocess

class RuleValidator:
    """Collection of static helpers that validate user input prior to issuing iptables commands."""

    IP_PATTERN = re.compile(r"^\d+\.\d+\.\d+\.\d+(\/\d+)?$")

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """IPv4 or CIDR; empty string == wildcard (always valid)."""
        ip = ip.strip()
        return ip == "" or bool(RuleValidator.IP_PATTERN.match(ip))

    @staticmethod
    def validate_port(port: str) -> bool:
        """Port range 1‑65535; empty string allowed as wildcard."""
        port = port.strip()
        return port == "" or (port.isdigit() and 1 <= int(port) <= 65535)

    @staticmethod
    def validate_flags(proto: str, flags) -> bool:
        """TCP flags are only meaningful when proto == 'tcp'."""
        return proto == "tcp" or not flags


class IptablesInterface:
    """Thin wrapper around iptables CLI via pkexec."""

    @staticmethod
    def _run(cmd: list[str]) -> subprocess.CompletedProcess:
        print("DEBUG Running:", " ".join(cmd))
        return subprocess.run(cmd, check=True, capture_output=True, text=True)

    @staticmethod
    def add_rule(
        proto: str,
        src_ip: str,
        dst_ip: str,
        src_port: str,
        dst_port: str,
        action: str,
        flags=None,
    ) -> None:
        """Insert a rule at position 1 of the INPUT chain."""
        cmd = [
            "pkexec",
            "iptables",
            "-I",
            "INPUT",
            "1",
            "-p",
            proto,
        ]

        if src_ip.strip():
            cmd += ["-s", src_ip]
        if dst_ip.strip():
            cmd += ["-d", dst_ip]
        if src_port.strip():
            cmd += ["--sport", src_port]
        if dst_port.strip():
            cmd += ["--dport", dst_port]

        if proto == "tcp" and flags:
            all_flags = "SYN,ACK,FIN,RST,PSH,URG"
            selected = ",".join(flags)
            cmd += ["--tcp-flags", all_flags, selected]

        cmd += ["-j", action]

        IptablesInterface._run(cmd)

    @staticmethod
    def list_rules() -> str:
        return IptablesInterface._run(
            ["pkexec", "iptables", "-L", "INPUT", "-v", "-n", "--line-numbers"]
        ).stdout

    @staticmethod
    def delete_rule(line_number: str) -> None:
        if not line_number.isdigit():
            raise ValueError(f"Invalid line number: {line_number}")
        IptablesInterface._run(["pkexec", "iptables", "-D", "INPUT", line_number])
