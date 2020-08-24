from scapy.all import *

import os
import time
import argparse

def get_args():
    """get_args called from main() to parse the command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', required=True)
    parser.add_argument('--csv', required=False)
    args = parser.parse_args()
    return args

def build_dict(pkt):
    """Function to build dictionary of every packet and return list of these dictionaries""" 
    
    proto = ['tcp', 'udp', 'ethernet', 'ipv4', 'ip', 'ipv6', 'icmp', 'ether']
    dicts = []

    for i in pkt:

        cnt = 0
        dic = {}
        while True:
            if(i.getlayer(cnt) is None):
                break
            if(i.getlayer(cnt).name.lower() in ['tcp','udp','icmp']):
                dic.update({'protocol':i.getlayer(cnt).name.lower()}) 
            if(i.getlayer(cnt).name.lower() not in proto):
                cnt+=1
                continue
            
            field_names = [field.name for field in i.getlayer(cnt).fields_desc]
            fields = {field_name: getattr(i, field_name) for field_name in field_names}
            
            dic.update(fields)
            cnt+=1
    
        dicts.append(dic)
    return dicts

def extract_csv(path, dicts):
    """Takes in list of dictionaries containing fields of each packet as key value pair
       and extract all key values to csv
    """

    all_keys = set([])
    for d in dicts:
        for i in d.keys():
            all_keys.add(i)    
    all_keys = sorted(all_keys)
    
    with open(path, 'w') as csv_file:
        header = str(','.join(all_keys)) + "\n"
        csv_file.write(header)
        for d in dicts:
            sorted_dict = dict(sorted(d.items()))

            row = ""
            for k in all_keys:
                val = sorted_dict.get(k, "")
                if( isinstance(val ,list) ):
                    val = str(val)
                    val = val.replace(',', '|')
                    row += "{},".format(val)
                else :
                    row += "{},".format(val)
            row += "\n"
            csv_file.write(row)


def main():
    """Program main entry"""

    args = get_args()
    csv_path = 'output.csv'
    pcap_path = args.pcap
    

    if(args.csv is not None):
        path = args.csv

    if not os.path.exists(args.pcap):
        print('Input pcap file "{}" does not exist'.format(args.pcap),
              file=sys.stderr)
        sys.exit(-1)

    if os.path.exists(csv_path):
        print('Output csv file "{}" already exists, '
              'won\'t overwrite'.format(csv_path),
              file=sys.stderr)
        sys.exit(-1)
    

    pkt  = rdpcap(pcap_path)

    dict_list = build_dict(pkt)

    extract_csv(csv_path, dict_list)


if __name__ == '__main__':
    main()
