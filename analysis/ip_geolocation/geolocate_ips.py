"""
Uses GeoLite2 City Database to geolocate a given newline separated list of IP addresses.
"""

import os
import subprocess as sp
import sys
import tqdm

import geoip2.database

basepath = os.path.dirname(os.path.abspath(__file__))

if len(sys.argv) < 2:
    print("Usage: %s <list_of_ip_addresses> > output_file.txt" % __file__)
    sys.exit()

to_analyze = sys.argv[1]

if not os.path.exists(to_analyze):
    print("ERROR: Could not open %s. Is this file readable?" % to_analyze)
    sys.exit()

reader = geoip2.database.Reader(
    os.path.join(basepath, "GeoLite2-City_20210126/GeoLite2-City.mmdb")
)

total_lines = int(sp.check_output(["wc", "-l", to_analyze]).split()[0])
pbar = tqdm.tqdm(total=total_lines)
print("ip,country,city,longitude,latitude")
with open(to_analyze, "r") as fd:
    line = fd.readline()
    while line:
        line = line.strip()
        if "," in line:
            ip = line.split(",")[0]
        else:
            ip = line
        try:
            response = reader.city(ip)
        except Exception as exc:
            country = "Unknown"
            city = "Unknown"
            longitude = "Unknown"
            latitude = "Unknown"
        else:
            country = response.country.names["en"]
            city = response.city.names["en"]
            longitude = response.location.longitude
            latitude = response.location.latitude
        print(",".join([str(x) for x in [line, country, city, longitude, latitude]]))
        pbar.update(1)
        line = fd.readline()
    pbar.close()
