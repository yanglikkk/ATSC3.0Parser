import platform

# 获取当前python版本号，选择合适的ip对比方法
python_major_num = int(platform.python_version().split('.')[0])
# 合并已经排序好的MIME数据包
def packaging(udp_packet_list):
    entire_mime_object = ''
    if(python_major_num == 2):
        for udp_packet in udp_packet_list:
            entire_mime_object += udp_packet[36:]
    else:
        for udp_packet in udp_packet_list:
            entire_mime_object += udp_packet[36:].decode('utf-8')
    return entire_mime_object
# 根据payload头部信息的内容起始偏移量进行排序
def sort_udp_packet(udp_packet_list):
    udp_packet_list.sort(key=lambda x: x[32:36])
    return udp_packet_list
# 输入不重复的udp包集集合
def sls_packaging(udp_packet_set):
    # 将集合列表化，进行排序
    return packaging(sort_udp_packet(list(udp_packet_set)))

