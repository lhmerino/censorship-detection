import pyasn
import csv

from pprint import pprint

def main():
    """
    Adds ASN numbers using pyasn to each of the IP addresses (each row in a csv)
    """

    # Initialize ASNDB
    asndb = pyasn.pyasn('../ipasn.gz')  # See pyasn docs to retrieve this file

    # Open the file where the information will be written to
    with open('../resources/results_blocked_ip_site_country_asn.csv', mode='w') as csv_file:
        headers = ['IP', 'Domain', 'Country', 'ASN']
        writer = csv.DictWriter(csv_file, fieldnames=headers, extrasaction='ignore')

        # Open the file where IP addresses are provided (each row)
        with open('../resources/results_blocked_ip_site_country.csv', 'r') as file:
            reader = csv.reader(file, delimiter=",")
            for i, pieces in enumerate(reader):
                # Get each IP address, corresponding information (to reprint) and the ASN number
                # by looking it up in the ASN DB provided by pyasn.
                block = {'IP': pieces[0], 'Domain': pieces[1], 'Country': pieces[2],
                             'ASN': asndb.lookup(pieces[0])[0]}
                writer.writerow(block)


if __name__ == '__main__':
    main()

