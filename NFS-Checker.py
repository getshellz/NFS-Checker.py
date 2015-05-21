#!/usr/bin/env python
#NFS-Checker by ha1fpint

import subprocess
import argparse
from datetime import datetime


def main():
	usage = """

NFS-Checker.py 

$ python ./%(prog)s <mode> <path>"""

	parser = argparse.ArgumentParser(usage=usage)
	parser.add_argument('-l', help='list input mode. path to list file.', dest='list_file', action='store')
	parser.add_argument('-x', help='xml input mode. path to Nessus/Nmap XML file.', dest='xml_file', action='store')
	parser.add_argument('-s', help='single input mode. path to target, remote URL or local path.', dest='target', action='store')
	opts = parser.parse_args()

	report = 'nfs-checker/NFS-Checker-' + str(datetime.now().time()) + '.html'
	ips = GetTargets(opts)
	db = {'targets': []}
	for ip in ips:
		print "[*] Getting NFS Shares " + str(ip)
		target_data = {}
		response = Check4Shares(ip)
		target_data['ip'] = str(ip)
		target_data['share'] = response
		print response
		db['targets'].append(target_data)
	buildReport(db, report, ips)


##################################################

def Check4Shares(ip):
	cmd = "showmount -e " + ip
	returncode, response = runCommand(cmd)
	return response

def runCommand(cmd):
    proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    stdout, stderr = proc.communicate()
    response = ''
    if stdout: response += str(stdout)
    if stderr: response += str(stderr)
    return proc.returncode, response.strip()

def GetTargets(opts):
    if opts.list_file:
        try:
            targets = open(opts.list_file).read().split()
            return targets
        except IOError:
            print '[!] Invalid path to list file: \'%s\'' % opts.list_file
            return
    elif opts.xml_file:
        # optimized portion of Peeper (https://github.com/invisiblethreat/peeper) by Scott Walsh (@blacktip)
        import xml.etree.ElementTree as ET
        try: tree = ET.parse(opts.xml_file)
        except IOError:
            print '[!] Invalid path to XML file: \'%s\'' % opts.xml_file
            return
        except ET.ParseError:
            print '[!] Not a valid XML file: \'%s\'' % opts.xml_file
            return
        root = tree.getroot()
        if root.tag.lower() == 'nmaprun':
            # parse nmap file
            targets = parseNmap(root)
        print '[*] Parsed targets:'
        for x in targets: print x
        return targets
    elif opts.target:
        targets = [opts.target]
    else:
        print '[!] Input mode required.'
        return 

def parseNmap(root):
    NFS_ports = [2049]
    targets = []
    # iterate through all host nodes
    for host in root.iter('host'):
        hostname = host.find('address').get('addr')
        # hostname node doesn't always exist. when it does, overwrite address previously assigned to hostanme
        hostname_node = host.find('hostnames').find('hostname')
        if hostname_node is not None: hostname = hostname_node.get('name')
        # iterate through all port nodes reported for the current host
        for item in host.iter('port'):
            state = item.find('state').get('state')
            if state.lower() == 'open':
                # service node doesn't always exist when a port is open
                service = item.find('service').get('name') if item.find('service') is not None else ''
                port = item.get('portid')
                if 'nfs' in service.lower() or int(port) in (NFS_ports):
                    proto = 'NFS'
                    ip = hostname
                    if not ip in targets:
                        targets.append(ip)
                elif not service:
                    # show the host and port for unknown services
                    print '[-] Unknown service: %s:%s' % (hostname, port)
    return targets



def buildReport(db, outfile, ips):
    live_markup = ''
    error_markup = ''
    dead_markup = ''
    # process markup for live targets
    for live in sorted(db['targets']):
        live_markup += "<tr><td class='tg-0ord'><pre>{0}</pre></td><td class='tg-0ord'><pre>{1}</pre></td></tr>\n".format(live['ip'],live['share'])
    # add markup to the report
    file = open(outfile, 'w')
    file.write("""
<!doctype html>
<head>
<title>NFS-Checker Report</title>
<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;border-color:#ccc;}
.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#ccc;color:#333;background-color:#fff;}
.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#ccc;color:#333;background-color:#f0f0f0;}
.tg .tg-0ord{text-align:left;background-color:#f0f0f0;}
.tg .tg-s6z2{text-align:center;background-color:#c0c0c0;}
</style>
</head>
<body>
<h3>NFS-Checker.py Report</h3>
<p><pre>Report generated for the addresses: %s </pre></p>
<table class="tg">
<tr>
    <th class="tg-s6z2">IP</th>
    <th class="tg-s6z2">Shares</th>
  </tr>
%s
</table>
</body>
</html>""" % (ips, live_markup))
    file.close()


if __name__ == "__main__": main()   
