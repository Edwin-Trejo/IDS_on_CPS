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

Inspect namespaces & created network devices

Show all network namespaces:

ip netns list
# or
ls -l /var/run/netns


Show all host network interfaces (including bridge + veth host sides):

ip link show
# more detail
ip -d link show


Show only veth interfaces (host side):

ip -d link show type veth


Show bridge and what’s attached:

# shows bridge state
ip link show br_lab

# show ports on the bridge
bridge link
# or (older)
brctl show br_lab


Show addresses for each namespace (run per namespace):

ip netns exec plc ip addr
ip netns exec scada ip addr
ip netns exec ids ip addr
ip netns exec attacker ip addr


Show routing table inside a namespace:

ip netns exec scada ip route

Enter a namespace (get a shell inside it)

Open an interactive shell inside a namespace (useful to run tools as if you were on that host):

sudo ip netns exec plc bash
# now you're inside the plc namespace; run commands like:
#   ss -ltnp
#   ps aux
#   curl http://10.10.10.10:502   # not a web server, but example
# exit to return to host

See processes / listening sockets inside a namespace

List listening TCP sockets and which process owns them (handy to confirm PLC simulator on port 502):

sudo ip netns exec plc ss -ltnp
sudo ip netns exec plc lsof -iTCP -sTCP:LISTEN -Pn || true


From the host you can also check which process is listening on br_lab or any port:

# check suricata systemd status
sudo systemctl status suricata

# OR if you ran suricata manually, grep its PID with:
ps aux | grep suricata

Check the veth pair mapping (host ↔ namespace)

List host-side veths and their peer names (short names used in the script):

ip -o link show | grep -E 'vh-|vn-'
# then inspect a specific interface:
ip -d link show vh-plc

Check Suricata (IDS) status & logs

If you ran Suricata with systemd:

sudo systemctl status suricata
sudo journalctl -u suricata -n 200 --no-pager


If you ran Suricata manually (foreground or nohup), check logs:

# common Suricata files
sudo ls -l /var/log/suricata
sudo tail -n 200 /var/log/suricata/fast.log
sudo tail -n 200 /var/log/suricata/suricata.log
# or check whatever file you redirected to (e.g., /tmp/suricata.log)

Check Node-RED (SCADA) is running

From the host, you can test connectivity to the Node-RED port in the scada namespace:

# uses the namespace's IP
curl -I http://10.10.10.20:1880 || true
# OR enter the scada namespace and check process
sudo ip netns exec scada ss -ltnp | grep 1880 || true
sudo ip netns exec scada ps aux | grep node-red || true


To access the Node-RED UI from your workstation, forward the port with SSH:

# on your workstation (outside VM). Replace vmuser and vm_ip with your VM's SSH creds.
ssh -L 1880:10.10.10.20:1880 vmuser@vm_ip
# then open http://localhost:1880 in your browser

Verify the PLC simulator and its logs (ground truth)

Confirm the PLC simulator is listening on 502 inside plc ns:

sudo ip netns exec plc ss -ltnp | grep :502 || true


Tail the simulator's CSV log:

sudo tail -n 50 /tmp/plc_log.csv

Capture live traffic on the bridge (see Modbus packets)

Run tcpdump on the bridge to observe Modbus (port 502) traffic:

sudo tcpdump -i br_lab -nn -vv port 502
# write to pcap for offline inspection:
sudo tcpdump -i br_lab -nn port 502 -w /tmp/modbus_test.pcap

Test communications (quick read/write)

From SCADA, try a read:

sudo ip netns exec scada python3 - <<'PY'
from pymodbus.client.sync import ModbusTcpClient
c = ModbusTcpClient('10.10.10.10', port=502)
c.connect()
r = c.read_holding_registers(0,2,unit=1)
print(r)
c.close()
PY


From Attacker, try a write (should generate IDS alert if Suricata running and rule matching):

sudo ip netns exec attacker python3 - <<'PY'
from pymodbus.client.sync import ModbusTcpClient
c = ModbusTcpClient('10.10.10.10', port=502)
c.connect()
c.write_coil(0, True, unit=1)
print('wrote coil 0')
c.close()
PY


Then check Suricata alerts (see logs section above).

Stopping/starting services

Stop PLC simulator in plc namespace (find its PID inside ns and kill):

sudo ip netns exec plc pkill -f plc_simulator.py || true
# or list processes and kill specific PID
sudo ip netns exec plc ps aux | grep plc_simulator.py


Stop Node-RED in scada namespace:

sudo ip netns exec scada pkill -f node-red || true


Stop Suricata (systemd):

sudo systemctl stop suricata
# or if running manually, kill the PID
ps aux | grep suricata
sudo pkill suricata || true

Clean up lab (remove namespaces and bridge)

If you want to tear down everything and return to a clean host:

# stop services first (see above), then:
for ns in plc scada ids attacker; do ip netns del $ns 2>/dev/null || true; done
ip link set br_lab down 2>/dev/null || true
ip link delete br_lab type bridge 2>/dev/null || true
# remove any vh-*/vn-* leftover
for ifc in $(ip -o link show | awk -F': ' '{print $2}'); do
  case "$ifc" in vh-*|vn-*) ip link delete "$ifc" 2>/dev/null || true ;; esac
done
