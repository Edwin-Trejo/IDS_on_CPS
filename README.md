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
