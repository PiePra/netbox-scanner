# netbox-scanner
api-script to fetch prefixes assigned with a given role, scan and compare reachable hosts of those prefixes with devices entered in netbox

create varfile.py for customization of api-token, server-url and role 

example output:
############# 10.90.15.0/24 #############
10.90.15.101 was scanned but not in Netbox.
10.90.15.102 was scanned but not in Netbox.
10.90.15.253 was scanned but not in Netbox.


