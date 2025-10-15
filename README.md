# IDS_on_CPS

This repo was created with the intention of documenting every step for this project

## Environment setup

In order to set the environment, we need to install a few thing on ubuntu
- set chmod +x setup_cps_lab.sh
- run the script setup_cps_lab.sh as sudo ./setup_cps_lab.sh

After everything is setup, try the following commands to verify it is working:
To show all network namespaces:
- ip netns list or ls -l /var/run/netns

Show all host network interfaces (including bridge + veth host sides):
- ip link show or ip -d link show

# CPS IDS Lab — Single-VM (Network Namespace) Guide

A compact, copy-pasteable guide for setting up a CPS (OpenPLC/Modbus) lab inside **one Ubuntu 22.04 VM** using Linux network namespaces.
This README contains everything from the setup script to start/stop commands, verification steps, troubleshooting, and next steps — ready to add to your project documentation.

---

## Overview

This lab emulates a small CPS network with four logical hosts inside one VM:

* **plc** — Modbus TCP PLC (Python simulator by default; can be replaced with OpenPLC)
* **scada** — SCADA/visualization (Node-RED)
* **ids** — IDS logical host (Suricata runs on the host bridge to observe traffic)
* **attacker** — attacker tools (pymodbus, nmap, scapy)

Network connectivity is provided by a Linux bridge (`br_lab`) and veth pairs connecting each namespace to the bridge. Suricata runs on the host listening on the bridge so it sees all Modbus traffic.

---

## Contents

* `setup_cps_lab.sh` — full corrected setup script (run with `sudo`)
* Quick start (commands to start services & tests)
* Inspection & verification commands
* Troubleshooting notes (permissions, interface name length, Suricata/no traffic)
* Cleanup instructions
* Next steps (OpenPLC, Node-RED flow, Suricata rules)

---

## Prerequisites (host VM)

* Host OS: **Ubuntu 22.04 LTS** (recommended)
* Suggested VM resources: **4 CPU threads, 8 GB RAM** (more if you run ELK / heavy rules)
* VirtualBox: you only need VirtualBox to run the VM; all lab components run inside the VM
* You must run commands that manipulate namespaces as **root** (use `sudo`)

---

## Quick start — run these after setup (copy/paste)

### 1) Start PLC simulator (plc namespace)

```bash
sudo ip netns exec plc bash -lc "nohup python3 /opt/cps_lab/plc_simulator.py >/tmp/plc_sim.stdout 2>&1 &"
```

### 2) Start Node-RED (scada namespace)

```bash
sudo ip netns exec scada bash -lc "cd /opt/cps_lab/scada_nr && nohup node-red >/tmp/node_red.stdout 2>&1 &"
```

Access Node-RED UI via SSH port-forward, or test from inside the namespace.

### 3) Start Suricata (on host, listen on bridge)

```bash
sudo suricata -i br_lab -c /etc/suricata/suricata.yaml --init-errors-fatal &
# (or run in foreground to watch logs)
```

### 4) Test read from SCADA (should return registers)

```bash
sudo ip netns exec scada python3 - <<'PY'
from pymodbus.client.sync import ModbusTcpClient
c = ModbusTcpClient('10.10.10.10', port=502)
c.connect()
r = c.read_holding_registers(0,2,unit=1)
print('regs', r.registers if r else r)
c.close()
PY
```

### 5) Test write from Attacker (should trigger IDS rule)

```bash
sudo ip netns exec attacker python3 - <<'PY'
from pymodbus.client.sync import ModbusTcpClient
c = ModbusTcpClient('10.10.10.10', port=502)
c.connect()
c.write_coil(0, True, unit=1)
c.close()
print('wrote coil 0')
PY
```

---

## Inspecting the environment

Run (use `sudo`):

* List namespaces:

```bash
sudo ip netns list
```

* List host interfaces (bridge + veth host sides):

```bash
sudo ip -d link show
sudo ip -d link show type veth
```

* Show bridge ports:

```bash
sudo bridge link
sudo brctl show br_lab || true
```

* View namespace IPs:

```bash
sudo ip netns exec plc ip addr
sudo ip netns exec scada ip addr
sudo ip netns exec ids ip addr
sudo ip netns exec attacker ip addr
```

* Check process/listeners in a namespace:

```bash
sudo ip netns exec plc ss -ltnp
sudo ip netns exec scada ss -ltnp
```

* Capture Modbus traffic:

```bash
sudo tcpdump -i br_lab -nn -vv port 502
# or write pcap
sudo tcpdump -i br_lab -nn port 502 -w /tmp/modbus_test.pcap
```

* Suricata logs:

```bash
sudo ls -l /var/log/suricata
sudo tail -n 200 /var/log/suricata/fast.log
```

---

## Troubleshooting

### `operation not permitted` when using `ip netns exec`

* Solution: run with `sudo`. Network namespace operations require root privileges:

```bash
sudo ip netns exec plc ip addr
```

### `name not a valid ifname` or interface creation fails

* Cause: Linux limits interface name length to **15 characters**. The fixed script uses short veth names (`vh-<ns>` and `vn-<ns>`).
* If you ran earlier failing script, run the cleanup in the script or manually delete leftover veth/bridge before re-running.

### Suricata sees no traffic / no alerts

* Confirm Suricata is running and listening on `br_lab`:

```bash
ps aux | grep suricata
sudo suricata -i br_lab -c /etc/suricata/suricata.yaml
```

* Capture traffic with `tcpdump` to confirm Modbus frames are present on the bridge.
* If rules don't match, capture pcap and inspect Modbus PDU bytes — rule offsets may need tuning (Modbus/TCP has a 7-byte MBAP header).

### PLC simulator not listening on port 502

* Verify process inside `plc` namespace:

```bash
sudo ip netns exec plc ss -ltnp | grep :502
sudo ip netns exec plc ps aux | grep plc_simulator.py
```

* Port <1024 requires root. The simulator is started inside the namespace using `sudo ip netns exec ...` so it runs as root in that namespace.

---

## Tear down / cleanup

Stop services first (inside namespaces or host), then delete namespaces & bridge:

```bash
# stop services
sudo ip netns exec plc pkill -f plc_simulator.py || true
sudo ip netns exec scada pkill -f node-red || true
sudo pkill suricata || true

# delete namespaces
for ns in plc scada ids attacker; do sudo ip netns del $ns 2>/dev/null || true; done

# remove bridge and leftover veths
sudo ip link set br_lab down 2>/dev/null || true
sudo ip link delete br_lab type bridge 2>/dev/null || true

# cleanup vh-/vn- interfaces if any remain
for ifc in $(ip -o link show | awk -F': ' '{print $2}'); do
  case "$ifc" in vh-*|vn-*) sudo ip link delete "$ifc" 2>/dev/null || true ;; esac
done
```

---

## Next steps

* **A — OpenPLC install**: replace the Python simulator with the OpenPLC runtime inside the `plc` namespace.
* **B — Node-RED flow**: importable Node-RED flow JSON that polls registers and displays a simple tank/pump dashboard.
* **C — Suricata rules & tests**: comprehensive Modbus ruleset (reads/writes, suspicious function codes, replay detection).
* **D — Docker-compose variant**: same network topology via Docker containers.

---

## License & attribution

You may copy or modify this documentation and the included scripts for your project. If used in reports or publications, please attribute the lab templates to your team and include notes about changes you made.

