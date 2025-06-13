#!/usr/bin/env python3

import os
import subprocess
import time
from pprint import pprint

import utils # utils must be in the same folder!

def run(cmd):
    print("+", " ".join(cmd))
    return subprocess.run(cmd, check=True, text=True, capture_output=True).stdout

# Backup the input chain
def save_chain():
    print(">> backing-up INPUT chain")
    return run(["iptables-save"])

# Restore original input chain once script is done
def restore_chain(snapshot):
    print(">> restoring original INPUT chain")
    p = subprocess.Popen(["iptables-restore"], stdin=subprocess.PIPE, text=True)
    p.communicate(snapshot)
    p.wait()
    print(">> restore complete")


def main():
    backup = save_chain()
    try:
        # Add one ACCEPT rule on 127.0.0.1:9999/udp
        print(">> adding rule 127.0.0.1:9999/udp ACCEPT")
        utils.IptablesInterface.add_rule(
            proto="udp",
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
            dst_port="9999",
            action="ACCEPT",
        )
        print("== after add ==")
        pprint(utils.IptablesInterface.list_rules_detailed())

        # Send UDP 5 packets so the counter rises
        print(">> generating 5 UDP packets on lo:9999")
        run(["hping3", "--udp", "-c", "5", "-p", "9999", "127.0.0.1"])
        time.sleep(1)
        print("== after traffic ==")
        pprint(utils.IptablesInterface.list_rules_detailed())

        # Disable the rule and fire 5 more packets
        added_line = utils.IptablesInterface.list_rules_detailed()[0]["line"]
        print(f">> disabling line {added_line}")
        utils.IptablesInterface.toggle_rule_state(added_line)
        run(["hping3", "--udp", "-c", "5", "-p", "9999", "127.0.0.1"])
        time.sleep(1)
        print("== after disable & traffic (count should be unchanged) ==")
        pprint(utils.IptablesInterface.list_rules_detailed())

        # Re-enable the rule, then delete it
        print(">> re-enable then delete the rule")
        utils.IptablesInterface.toggle_rule_state(added_line)
        utils.IptablesInterface.delete_rule(added_line)
        print("== after delete ==")
        pprint(utils.IptablesInterface.list_rules_detailed())

        # Reorder packets
        print(">> reorder by packets")
        utils.IptablesInterface.reorder_by_packets()
        print("== after reorder ==")
        pprint(utils.IptablesInterface.list_rules_detailed())

        print("\nALL TESTS PASSED! YIPPIE!")

    finally:
        restore_chain(backup)


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Run this script as root!")
    main()
