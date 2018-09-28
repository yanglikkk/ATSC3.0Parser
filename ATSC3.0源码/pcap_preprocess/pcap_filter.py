import socket
from binascii import hexlify
import platform

class IP_HEADER():
    SRC_IP_OFFSET = 12
    SRC_IP_LENTH = 4
    DST_IP_OFFSET = 16
    DST_IP_LENGTH = 4

class UDP_HEADER():
    SRC_PORT_OFFSET = 0
    SRC_PORT_LENGTH = 2
    DST_PORT_OFFSET = 2
    DST_PORT_LENGTH = 2

# 将人可读的ip地址转换为对应ascii码值的字符串
def human_read_ip_to_asciistr(human_read_ip):
    return ''.join('%s' %chr((int(x))) for x in human_read_ip.split('.'))
# python3版本将bytes转化成str类型
def bytes_to_str3(input_bytes):
    return ''.join('%s' %chr(x) for x in input_bytes)
# python2版本raw_ip为str，不需要转化
def compare_ip2(human_read_ip, raw_ip):
    return human_read_ip_to_asciistr(human_read_ip) == raw_ip
# python3版本raw_ip为bytes
def compare_ip3(human_read_ip, raw_ip):
    return human_read_ip_to_asciistr(human_read_ip) == bytes_to_str3(raw_ip)
# 
def compare_port2(human_read_port, raw_port):
    port = int(human_read_port)
    port_num1 = port // 256
    port_num2 = port % 256
    return ''.join('%s%s' %(chr(port_num1), chr(port_num2))) == raw_port
# 
def compare_port3(human_read_port, raw_port):
    port = int(human_read_port)
    port_num1 = port // 256
    port_num2 = port % 256
    return ''.join('%s%s' %(chr(port_num1), chr(port_num2))) == bytes_to_str3(raw_port)

# 获取当前python版本号，选择合适的ip对比方法
python_major_num = int(platform.python_version().split('.')[0])
if(python_major_num == 2):
    compare_ip = compare_ip2
    compare_port = compare_port2
else:
    compare_ip = compare_ip3
    compare_port = compare_port3

# 给定pcap包流数据，ipV4地址，UDP端口，过滤pcap数据包，返回满足要求的数据包抓取时间和包流数据
def pcap_packet_filter(pcap_packet_set, dst_ip, udp_dst_port=None):
    # todo IPV4分析
    ipv4_header_offset = 0
    ipv4_header_lenth = 20

    udp_header_offset = ipv4_header_lenth + ipv4_header_offset
    filtered_pcaket_time = []
    flitered_ipv4_packet_set = []
    # 获取dst ip和udp dst port的偏移值
    dst_start_offset = IP_HEADER.DST_IP_OFFSET
    dst_end_offset = IP_HEADER.DST_IP_OFFSET + IP_HEADER.DST_IP_LENGTH
    udp_dst_port_start_offset = udp_header_offset + UDP_HEADER.DST_PORT_OFFSET
    udp_dst_port_end_offset = udp_dst_port_start_offset + UDP_HEADER.DST_PORT_LENGTH
    for pcap_time, pcap_data in pcap_packet_set:
        if(not compare_ip(dst_ip, pcap_data[dst_start_offset:dst_end_offset])):
            continue
        if(udp_dst_port != None):
            if(not compare_port(udp_dst_port, pcap_data[udp_dst_port_start_offset:udp_dst_port_end_offset])):
                continue
        filtered_pcaket_time.append(pcap_time)
        flitered_ipv4_packet_set.append(pcap_data)
    return [filtered_pcaket_time, flitered_ipv4_packet_set]