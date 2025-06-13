import re
import subprocess
from typing import List, Dict, Any, Optional


class RuleValidator:
    _IP = re.compile(r"^\d+\.\d+\.\d+\.\d+(?:\/\d+)?$")

    @staticmethod
    def validate_ip(ip: str) -> bool:
        return ip.strip() == "" or bool(RuleValidator._IP.match(ip.strip()))

    @staticmethod
    def validate_port(port: str) -> bool:
        port = port.strip()
        return port == "" or (port.isdigit() and 1 <= int(port) <= 65535)

    @staticmethod
    def validate_flags(proto: str, flags: Optional[list[str]]) -> bool:
        return proto == "tcp" or not flags


class IptablesInterface:
    @staticmethod
    def _run(cmd: List[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(e.stderr.strip() or str(e)) from None

    @staticmethod
    def _rules_S() -> List[str]:
        out = IptablesInterface._run(["pkexec", "iptables", "-S", "INPUT"]).stdout
        return [ln for ln in out.splitlines() if ln.startswith("-A INPUT")]

    @staticmethod
    def _rules_L() -> List[str]:
        out = IptablesInterface._run(
            ["pkexec", "iptables", "-L", "INPUT", "-v", "-n", "--line-numbers"]
        ).stdout
        return [ln for ln in out.splitlines() if re.match(r"^\s*\d+", ln)]

    # CRUD
    @staticmethod
    def add_rule(
        proto: str,
        src_ip: str = "",
        dst_ip: str = "",
        src_port: str = "",
        dst_port: str = "",
        action: str = "ACCEPT",
        flags: Optional[list[str]] = None,
        comment: str | None = None,
    ) -> None:
        cmd: List[str] = ["pkexec", "iptables", "-I", "INPUT", "1", "-p", proto]
        if src_ip:
            cmd += ["-s", src_ip]
        if dst_ip:
            cmd += ["-d", dst_ip]
        if src_port:
            cmd += ["--sport", src_port]
        if dst_port:
            cmd += ["--dport", dst_port]
        if proto == "tcp" and flags:
            cmd += ["--tcp-flags", "SYN,ACK,FIN,RST,PSH,URG", ",".join(flags)]
        cmd += ["-j", action]

        parts = ["gui"]
        if flags:
            parts.append(f"flags={','.join(flags)}")
        if comment:
            parts.append(comment)
        cmd += ["-m", "comment", "--comment", ";".join(parts)]

        IptablesInterface._run(cmd)

    @staticmethod
    def delete_rule(line_number: str) -> None:
        if not line_number.isdigit():
            raise ValueError("Line number must be numeric")
        IptablesInterface._run(["pkexec", "iptables", "-D", "INPUT", line_number])

    @staticmethod
    def toggle_rule_state(line_number: str) -> None:
        """
        Flip between:

            ... -j ACCEPT/DROP
        and:
            ... -j RETURN  -m comment --comment "DISABLED:ACCEPT/DROP"
        """
        if not line_number.isdigit():
            raise ValueError("Line number must be numeric")

        idx = int(line_number) - 1
        specs = IptablesInterface._rules_S()
        if idx >= len(specs):
            raise IndexError("Line number out of range")

        tokens = specs[idx].split()[2:]          # drop “-A INPUT”
        try:
            j_idx = tokens.index("-j")
        except ValueError:
            raise RuntimeError("Malformed rule (no -j)")

        jump = tokens[j_idx + 1]

        # Re-enable
        if jump == "RETURN":
            # locate the "--comment DISABLED:XYZ" block
            if "--comment" in tokens:
                c_idx = tokens.index("--comment")
                text = tokens[c_idx + 1].strip('"')
                m = re.match(r"DISABLED:([A-Z]+)", text)
                orig = m.group(1) if m else "DROP"
                del tokens[c_idx - 2 : c_idx + 2]
            else:
                orig = "DROP"

            j_idx = tokens.index("-j")
            tokens[j_idx + 1] = orig

        # Disable
        else:
            orig = jump
            tokens[j_idx + 1] = "RETURN"
            tokens += [
                "-m", "comment", "--comment", f'DISABLED:{orig}'
            ]

        IptablesInterface._run(
            ["pkexec", "iptables", "-R", "INPUT", line_number, *tokens]
        )


    @staticmethod
    def list_rules_detailed() -> List[Dict[str, Any]]:
        L, S = IptablesInterface._rules_L(), IptablesInterface._rules_S()
        out: List[Dict[str, Any]] = []
        for l, s in zip(L, S):
            cols = l.split()
            if len(cols) < 9:
                continue
            line, pkts, proto, src, dst = cols[0], cols[1], cols[4], cols[8], cols[9]
            dpt = re.search(r"dpt:(\d+)", l)
            spt = re.search(r"spt:(\d+)", l)
            ports = dpt.group(1) if dpt else (spt.group(1) if spt else "-")
            fm = re.search(r"--tcp-flags\s+\S+\s+([A-Z,]+)", s)
            flags = fm.group(1) if fm else "-"
            disabled = "RETURN" in s and "DISABLED" in s
            out.append(
                dict(
                    line=line,
                    pkts=pkts,
                    proto=proto,
                    src=src,
                    dst=dst,
                    ports=ports,
                    flags=flags,
                    disabled=disabled,
                    spec=s,
                )
            )
        return out

    @staticmethod
    def reorder_by_packets() -> None:
        rules = IptablesInterface.list_rules_detailed()
        rules.sort(key=lambda r: int(r["pkts"]), reverse=True)
        IptablesInterface._run(["pkexec", "iptables", "-F", "INPUT"])
        for r in rules:
            IptablesInterface._run(
                ["pkexec", "iptables", "-A", "INPUT", *r["spec"].split()[2:]]
            )
