# -*- coding: UTF-8 -*-
from __future__ import unicode_literals, print_function, division
import sys
import json
from collections import defaultdict, Counter


def get_ip_data(ip, records):
    data = {}
    bcs = set()
    uas = set()
    for record in records:
        if record['@fields']['remote_addr'] == ip:
            bcs.add(record['@fields']['browser_code'])
            uas.add(record['@fields']['http_user_agent'])
    data['bcs'] = bcs
    data['uas'] = uas
    return data


file_name = sys.argv[1]

with open(file_name) as f:
    lines = f.readlines()

records = []
for line in lines:
    try:
        obj_line = json.loads(line)
    except Exception as e:
        print('err: {}'.format(e.message))
    else:
        records.append(obj_line)

print('read records done.')
tss = [r['@timestamp'] for r in records]
start_time = min(tss)
end_time = max(tss)
print('stat for: {} ~ {}\n'.format(start_time, end_time))
requests = [r['@fields']['request'] for r in records]

print('top 10 uri: ')
for url, count in Counter(requests).most_common(10):
    print('{}, {}'.format(url, count))
print()

ip2bytes = defaultdict(int)
for record in records:
    ip = record['@fields']['remote_addr']
    bytes = int(record['@fields']['body_bytes_sent'])

    ip2bytes[ip] += bytes

ips = [r['@fields']['remote_addr'] for r in records]
print('top 10 ips(request):')
for ip, count in Counter(ips).most_common(10):
    data = get_ip_data(ip, records)
    print('{}, {}, {} bcs, {} uas: {}'.format(ip,
                                              count,
                                              len(data['bcs']),
                                              len(data['uas']),
                                              data['uas']))
print()

print('top 10 ips:')
for ip, bytes in Counter(ip2bytes).most_common(10):
    print('{}, {}'.format(ip, bytes))
print()

total_bytes = sum(ip2bytes.values())
print('total body bytes sent: {}({} Mib)'.format(total_bytes, total_bytes / (1024 * 1024)))
