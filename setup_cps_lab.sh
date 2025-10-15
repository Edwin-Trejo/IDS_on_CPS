#!/usr/bin/env bash
set -euo pipefail
# setup_cps_lab.sh - single-VM CPS lab using Linux network namespaces (corrected)
# Usage: sudo ./setup_cps_lab.sh
# Tested on Ubuntu 22.04 LTS (Jammy). Adjust if necessary.

LAB_BRIDGE=br_lab
NAMESPACES=(plc scada ids attacker)
declare -A IPS=( ["plc"]="10.10.10.10/24" ["scada"]="10.10.10.20/24" ["ids"]="10.10.10.30/24" ["attacker"]="10.10.10.40/24" )
LABDIR=/opt/cps_lab
SUDO_USER=${SUDO_USER:-$(logname 2>/dev/null || echo root)}

echo "=== CPS LAB SETUP (namespaces) ==="

## -------------------------
## 0) Basic cleanup (idempotent)
## -------------------------
echo "-> cleaning previous partial setup (if any)..."
# delete namespaces if exist
for ns in "${NAMESPACES[@]}"; do
  ip netns del "$ns" 2>/dev/null || true
done

# delete common veth patterns (be conservative)
for ifc in $(ip -o link show | awk -F': ' '{print $2}'); do
  case "$ifc" in
    vh-*|vn-*)
      ip link delete "$ifc" 2>/dev/null || true
      ;;
  esac
done

# delete bridge if present
ip link set $LAB_BRIDGE down 2>/dev/null || true
ip link delete $LAB_BRIDGE type bridge 2>/dev/null || true

echo "cleanup finished."

## -------------------------
## 1) Packages & prerequisites
## -------------------------
echo "-> updating apt and installing prerequisites..."
apt update -y
DEBS="iproute2 iptables bridge-utils net-tools python3 python3-pip python3-venv git nodejs npm build-essential libmodbus-dev suricata tcpdump"
apt install -y $DEBS

# ensure `node` binary exists (some distros have nodejs only)
if ! command -v node >/dev/null 2>&1 && command -v nodejs >/dev/null 2>&1; then
  ln -sf "$(command -v nodejs)" /usr/bin/node
fi

echo "packages done."

## -------------------------
## 2) Create bridge and namespaces + veths (short names)
## -------------------------
echo "-> creating bridge $LAB_BRIDGE"
ip link add name $LAB_BRIDGE type bridge || true
ip link set $LAB_BRIDGE up

echo "-> creating namespaces"
for ns in "${NAMESPACES[@]}"; do
  ip netns add "$ns" || true
done

echo "-> creating short-named veth pairs and assigning IPs"
for ns in "${NAMESPACES[@]}"; do
  vh="vh-${ns}"    # host side (<=15 chars)
  vn="vn-${ns}"    # ns side
  # if interface already exists from prior run, delete then recreate to be safe
  ip link delete "$vh" 2>/dev/null || true
  ip link add "$vh" type veth peer name "$vn"
  ip link set "$vn" netns "$ns"
  ip link set "$vh" master $LAB_BRIDGE
  ip link set "$vh" up
  ip netns exec $ns ip link set lo up
  ip netns exec $ns ip link set "$vn" up
  ip netns exec $ns ip addr add "${IPS[$ns]}" dev "$vn"
done

# Enable IPv4 forward on host for completeness
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "namespaces and veths configured."

## -------------------------
## 3) Python env & pymodbus (PLC simulator)
## -------------------------
echo "-> preparing lab dir and Python dependencies..."
mkdir -p "$LABDIR"
chown "$SUDO_USER":"$SUDO_USER" "$LABDIR" || true

# use pip to install pymodbus (fixed version used earlier)
python3 -m pip install --upgrade pip
python3 -m pip install pymodbus==2.5.3 gevent >/dev/null

cat > "$LABDIR/plc_simulator.py" <<'PY'
#!/usr/bin/env python3
# Simple Modbus TCP PLC simulator using pymodbus (holds registers and coils).
import logging
from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.transaction import ModbusSocketFramer
import threading, time, csv, os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("plc_sim")

# initial data: 100 holding registers, 100 coils
store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, [0]*100),
    co=ModbusSequentialDataBlock(0, [0]*100),
    hr=ModbusSequentialDataBlock(0, [0]*100),
    ir=ModbusSequentialDataBlock(0, [0]*100)
)
context = ModbusServerContext(slaves=store, single=True)

LOG_PATH='/tmp/plc_log.csv'
def logger_thread():
    # logs the first 8 registers/coils to CSV every second
    # write header if new
    first = not os.path.exists(LOG_PATH)
    with open(LOG_PATH,'a',newline='') as f:
        w = csv.writer(f)
        if first:
            w.writerow(["timestamp","coils0-7","hr0-7"])
        while True:
            coils = context[0].getValues(1, 0, count=8)
            hrs = context[0].getValues(3, 0, count=8)
            w.writerow([time.time(), ",".join(map(str,coils)), ",".join(map(str,hrs))])
            f.flush()
            time.sleep(1)

if __name__ == "__main__":
    t = threading.Thread(target=logger_thread, daemon=True)
    t.start()
    logger.info("Starting Modbus TCP Simulator on port 502")
    StartTcpServer(context, framer=ModbusSocketFramer, address=("0.0.0.0", 502))
PY

chmod +x "$LABDIR/plc_simulator.py"
chown "$SUDO_USER":"$SUDO_USER" "$LABDIR/plc_simulator.py"

cat > "$LABDIR/plc_logger_readme.txt" <<'TXT'
PLC simulator logs to /tmp/plc_log.csv
Columns: timestamp, coils0-7 (comma-separated), hr0-7 (comma-separated)
TXT
chown "$SUDO_USER":"$SUDO_USER" "$LABDIR/plc_logger_readme.txt"

echo "plc simulator ready at $LABDIR/plc_simulator.py"

## -------------------------
## 4) Node-RED (SCADA) prep
## -------------------------
echo "-> installing Node-RED (global) and preparing SCADA folder"
npm install -g --unsafe-perm node-red >/dev/null 2>&1 || true

SCADA_DIR="$LABDIR/scada_nr"
mkdir -p "$SCADA_DIR"
chown "$SUDO_USER":"$SUDO_USER" "$SCADA_DIR"
# create minimal package and install modbus node so flows can use it
pushd "$SCADA_DIR" >/dev/null
sudo -u "$SUDO_USER" npm init -y >/dev/null 2>&1 || true
sudo -u "$SUDO_USER" npm install node-red-contrib-modbus >/dev/null 2>&1 || true
popd >/dev/null

echo "Node-RED prepared in $SCADA_DIR (will be run inside scada namespace)."

## -------------------------
## 5) Suricata local rule
## -------------------------
echo "-> writing a basic Suricata local rule for Modbus write single coil (func 0x05)"
SURICATA_RULES_DIR=/etc/suricata/rules
LOCAL_RULES=${SURICATA_RULES_DIR}/local.rules
mkdir -p "$SURICATA_RULES_DIR"
cat > "$LOCAL_RULES" <<'RULE'
# local suricata rules - detect modbus function code 0x05 (Write Single Coil)
# note: offset:7 assumes Modbus/TCP header (transaction ID/protocol/length/unit id)
alert tcp any any -> any 502 (msg:"MODBUS Write Single Coil (func 0x05)"; flow:to_server,established; content:"|05|"; offset:7; depth:1; sid:1000001; rev:1;)
RULE

echo "Local rule written to $LOCAL_RULES"

## -------------------------
## 6) Final notes & quick start reminders
## -------------------------
cat > "$LABDIR/README_START.txt" <<'TXT'
CPS Lab quick-start (run these after the script completes):

# 1) Start PLC simulator in plc namespace (background)
sudo ip netns exec plc bash -lc "nohup python3 /opt/cps_lab/plc_simulator.py >/tmp/plc_sim.stdout 2>&1 &"

# 2) Start Node-RED in scada namespace (background)
sudo ip netns exec scada bash -lc "cd /opt/cps_lab/scada_nr && nohup node-red >/tmp/node_red.stdout 2>&1 &"

# 3) Start Suricata on the host listening on bridge (br_lab)
sudo suricata -i br_lab -c /etc/suricata/suricata.yaml --init-errors-fatal &
# or run in foreground to watch logs:
# sudo suricata -i br_lab -c /etc/suricata/suricata.yaml

# 4) Test from scada namespace (read)
sudo ip netns exec scada bash -lc "python3 - <<'PY'
from pymodbus.client.sync import ModbusTcpClient
c = ModbusTcpClient('10.10.10.10', port=502)
c.connect()
r = c.read_holding_registers(0,2,unit=1)
print('regs', r.registers if r else r)
c.close()
PY"

# 5) Test attack from attacker namespace (write coil -> should trigger rule)
sudo ip netns exec attacker bash -lc "python3 - <<'PY'
from pymodbus.client.sync import ModbusTcpClient
c = ModbusTcpClient('10.10.10.10', port=502)
c.connect()
c.write_coil(0, True, unit=1)
c.close()
print('wrote coil 0')
PY"

# Check Suricata alerts:
# sudo grep -i "MODBUS Write Single Coil" /var/log/suricata/fast.log || sudo tail -n 200 /var/log/suricata/alert

# PLC logs (ground truth):
# sudo tail -n 30 /tmp/plc_log.csv

TXT
chown "$SUDO_USER":"$SUDO_USER" "$LABDIR/README_START.txt"

echo "=== SETUP COMPLETE ==="
