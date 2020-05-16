import nmap
import requests
import json
#varfile.py has to be created
from varfile import token, server, role

headers = {'Authorization': 'Token ' + token}

# call netbox api to get all prefixes assigned with specific role
url = 'http://' + server + '/api/ipam/prefixes/?role=' + role
req = requests.get(url=url, headers=headers, verify=False)
result = json.loads(req.text)["results"]
for r in result:
    scan_hosts = []
    api_hosts = []
    scan_diff = []
    api_diff = []
    print('############# '+ r['prefix'] + ' #############')
    ## scan prefix
    v_nmap = nmap.PortScanner()
    v_nmap.scan(hosts=r['prefix'], arguments='-n -sP -PE')
    scan_hosts = v_nmap.all_hosts()
    scan_hosts.sort()
    # call netbox api get every child of prefix
    url = 'http://' + server + '/api/ipam/ip-addresses/?parent=' + r['prefix'].replace('/', '%2F')
    req = requests.get(url=url, headers=headers, verify=False)
    response = json.loads(req.text)['results']
    for x in response:
        api_hosts.append(x["address"][:-3])
    api_hosts.sort()

    for item in scan_hosts:
        if item not in api_hosts:
            scan_diff.append(item)

    for item in api_hosts:
        if item not in scan_hosts:
            api_diff.append(item)
    
    if len(scan_diff) == 0 and len(api_diff) == 0:
        print("there is no difference")
    for item in scan_diff:
        print(item + " was scanned but not in Netbox.")
    for item in api_diff:
        print(item + " was in netbox but not scanned. Depleted?")
