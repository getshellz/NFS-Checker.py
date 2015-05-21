#!/usr/bin/env python
#NFS-Checker by ha1fpint

from subprocess import call

with open("NFS-ips.txt") as f:
	ips = [x.strip('\n') for x in f.readlines()]
for ip in ips:
	print ip
	call(["showmount", "-e", ip])