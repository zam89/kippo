


import os, time, anydbm, datetime
from kippo.core.honeypot import HoneyPotCommand
from twisted.internet import reactor
from kippo.core.config import config
from kippo.core.userdb import UserDB
from kippo.core import utils

commands = {}

class command_iptables(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0].strip() in ('-h', '--help'):
            self.writeln(
                "iptables v1.4.12",
                "",
                "Usage: iptables -[ACD] chain rule-specification [options]",
                "       iptables -I chain [rulenum] rule-specification [options]",
                "       iptables -R chain rulenum rule-specification [options]",
                "       iptables -D chain rulenum [options]",
                "       iptables -[LS] [chain [rulenum]] [options]",
                "       iptables -[FZ] [chain] [options]",
                "       iptables -[NX] chain",
                "       iptables -E old-chain-name new-chain-name",
                "       iptables -P chain target [options]",
                "       iptables -h (print this help information)",
                "",
                "Commands:",
                "Either long or short options are allowed.",
                "  --append  -A chain           Append to chain",
                "  --check   -C chain           Check for the existence of a rule",
                "  --delete  -D chain           Delete matching rule from chain",
                "  --delete  -D chain rulenum",
                "                               Delete rule rulenum (1 = first) from chain",
                "  --insert  -I chain [rulenum]",
                "                               Insert in chain as rulenum (default 1=first)",
                "  --replace -R chain rulenum",
                "                               Replace rule rulenum (1 = first) in chain",
                "  --list    -L [chain [rulenum]]",
                "                               List the rules in a chain or all chains",
                "  --list-rules -S [chain [rulenum]]",
                "                               Print the rules in a chain or all chains",
                "  --flush   -F [chain]         Delete all rules in  chain or all chains",
                "  --zero    -Z [chain [rulenum]]",
                "                               Zero counters in chain or all chains",
                "  --new     -N chain           Create a new user-defined chain",
                "  --delete-chain",
                "            -X [chain]         Delete a user-defined chain",
                "  --policy  -P chain target",
                "                               Change policy on chain to target",
                "  --rename-chain",
                "            -E old-chain new-chain",
                "                               Change chain name, (moving any references)",
                "Options:",
                "    --ipv4  -4                 Nothing (line is ignored by ip6tables-restore)",
                "    --ipv6  -6                 Error (line is ignored by iptables-restore)",
                "[!] --proto -p proto           protocol: by number or name, eg. `tcp'",
                "[!] --source    -s address[/mask][...]",
                "                               source specification",
                "[!] --destination -d address[/mask][...]",
                "                               destination specification",
                "[!] --in-interface -i input name[+]",
                "                               network interface name ([+] for wildcard)",
                " --jump -j target",
                "                               target for rule (may load target extension)",
                "  --goto      -g chain",
                "                             jump to chain with no return",
                "  --match   -m match",
                "                               extended match (may load extension)",
                "  --numeric -n                 numeric output of addresses and ports",
                "[!] --out-interface -o output name[+]",
                "                               network interface name ([+] for wildcard)",
                "  --table   -t table           table to manipulate (default: `filter')",
                "  --verbose -v                 verbose mode",
                "  --line-numbers               print line numbers when listing",
                "  --exact   -x                 expand numbers (display exact values)",
                "[!] --fragment  -f             match second or further fragments only",
                "  --modprobe=<command>         try to insert modules using this command",
                "  --set-counters PKTS BYTES    set the counter during insert/append",
                "[!] --version   -V             print package version.",
            )
            for l in output:
                    self.writeln(l)
                self.exit()
        else:
            output = (
                "iptables v1.4.12: unknown option '$s'",
                "Try `iptables -h' or 'iptables --help' for more information.", % (arg,)
                )
            for l in output:
                self.writeln(l)
            self.exit()

commands['/sbin/iptables'] = command_iptables
