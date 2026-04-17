def detect_os(nm, ip):
    os_name = "Unknown"
    vendor = "Unknown"

    try:
        if 'osmatch' in nm[ip]:
            os_name = nm[ip]['osmatch'][0]['name']
    except:
        pass

    try:
        if 'vendor' in nm[ip]['addresses']:
            vendor = nm[ip]['vendor']
    except:
        pass

    return os_name, vendor
