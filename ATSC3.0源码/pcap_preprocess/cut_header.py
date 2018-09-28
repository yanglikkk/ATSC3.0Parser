# 输入参数为一个完整的udp数据包，去除udp包头部分，返回值为去除包头的udp数据
def cut_udp_header(udp_packet):
    udp_data = udp_packet[28:]
    return udp_data

def cut_header(sorted_dict):
    data_list = []
    for i,v in sorted_dict.items():
        for j in v:
            data_list.append(j[int('0' + str(repr(j[30]))[2:5], 16) * 4 + 4 + 28 :])
        sorted_dict[i] = data_list
    return sorted_dict
