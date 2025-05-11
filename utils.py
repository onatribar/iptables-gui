import re
import subprocess

class RuleValidator:
    @staticmethod
    def validate_ip(ip):
        if ip.strip() == "":
            return True
        return re.match(r"^\d+\.\d+\.\d+\.\d+(\/\d+)?$", ip)

    @staticmethod
    def validate_port(port):
        return port.isdigit() and 1 <= int(port) <= 65535

class IptablesInterface:
    @staticmethod
    def add_rule(proto, src_ip, dst_ip, dst_port, action, flags=None):
        cmd = ["pkexec", "iptables", "-I", "INPUT", "1", "-p", proto]

        if src_ip.strip(): cmd += ["-s", src_ip]
        if dst_ip.strip(): cmd += ["-d", dst_ip]
        if dst_port.strip(): cmd += ["--dport", dst_port]

        if proto == "tcp" and flags:
            all_flags = "SYN,ACK,FIN,RST,PSH,URG"
            selected = ",".join(flags)
            cmd += ["--tcp-flags", all_flags, selected]

        cmd += ["-j", action]

        print("DEBUG Running:", " ".join(cmd))
        subprocess.run(cmd, check=True)


    @staticmethod
    def list_rules():
        result = subprocess.run([
            "pkexec", "iptables", "-L", "INPUT", "-v", "-n", "--line-numbers"
        ], check=True, capture_output=True, text=True)
        return result.stdout

    @staticmethod
    def delete_rule(line_number):
        if not line_number.isdigit():
            raise ValueError(f"Invalid line number: {line_number}")

        cmd = ["pkexec", "iptables", "-D", "INPUT", line_number]
        print("DEBUG Running:", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print("ERROR:", result.stderr)
            raise Exception(f"Failed to delete rule at line {line_number}")
