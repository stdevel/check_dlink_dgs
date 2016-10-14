# check_dlink_dgs
`check_dlink_dgs` is a Nagios / Icinga plugin for monitoring D-Link DGS managed switches.
The plugin checks for disconnected ports and also gathers package counter metrics which can be exposed as performance data. The switch is connected via SNMP (*version 1 or 2*).

# Requirements
The plugin requires Python 2.6 or newer - it also requires the `pysnmp` module.

# Usage
By default, the script checks particular ports for connectivity, it is also possible to auto-detect available ports and check all those ports. The script also supports performance data for data visualization. The following additional parameters can adjust this behavior:

| Parameter | Description |
|:----------|:------------|
| `-d` / `--debug` | enable debugging outputs (*default: no*) |
| `-h` / `--help` | shows help and quits |
| `-P` / `--enable-perfdata` | enables performance data (*default: no*) |
| `-H` / `--host` | defines the switch hostname or IP |
| `-c` / `--snmp-community` | defines the SNMP community (*default: public*) |
| `-V` / `--snmp-verions` | defines the SNMP version (*default: 2c*) |
| `-p` / `--snmp-port` | defines the SNMP port (*default: 161*) |
| `-P` / `--ports` | defines one or more ports for monitoring |
| `-a` / `--all-ports` | monitors all ports (*default: no*) |
| `-A` / `--active-ports` | monitors all active ports (*default: no*)  |
| `--version` | prints programm version and quits |

## Examples
The following command checks a particular port for connectivity:
```
$ ./check_dlink_dgs.py -H 192.168.178.1 -P 1
OK: All specified ports connected |
```

Checking particular ports by ranges, customized SNMP community:
```
$ ./check_dlink_dgs.py -H 192.168.178.1 -c giertz -P 1,3 -P 4-5
OK: All specified ports connected |
```

Gathering performance data of a dedicated port:
```
$ ./check_dlink_dgs.py -H 192.168.178.1 -P 26 -e
OK: All specified ports connected | 'inOct ESXi/10G'=577123318111 'outOct ESXi/10G'=1269140449325
```

Checking all available ports:
```
$ ./check_dlink_dgs.py -H 192.168.178.1 -a
CRITICAL: Disconnected port(s) 2,7,14,15,16,17,19,20,21,22,23,28 |
```

Checking all connected ports:
```
$ ./check_dlink_dgs.py -H 192.168.178.1 -A
OK: All specified ports connected |
```

# Configuration
This repository contains a NRPE (*`check_dlink_dgs.cfg`*) and Icinga2 (*`check_dlink_dgs-icinga2.conf`*) configuration example - take a look!
