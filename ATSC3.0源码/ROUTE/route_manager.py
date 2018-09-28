from pcap_preprocess import pcap_filter, cut_header
from ROUTE import route_packaging, mime_parser
import os, platform
from io import StringIO
from atsc_utils import xml_util

# 获取当前python版本号，选择合适的ip对比方法
python_major_num = int(platform.python_version().split('.')[0])


# 将16进制字节代表的raw_tsi转化为实际数值
def tsi_to_value(raw_tsi):
    if(python_major_num == 2):
        tsi_value = 0
        for ch in raw_tsi:
            tsi_value = tsi_value * 256 + ord(ch)
        return tsi_value
    else:
        tsi_value = 0
        for num in raw_tsi:
            tsi_value = tsi_value * 256 + num
        return tsi_value

# 保存mime内容文件
def save_mime_content_file(mime_content_dict, service_dir_name):
    if not os.path.exists(service_dir_name):
        os.makedirs(service_dir_name)
    for mime_file_name, mime_file_content in mime_content_dict.items():
            # 同一服务的MIME内容进行处理
            file_name = service_dir_name + os.sep + mime_file_name
            file_obj = open(service_dir_name + os.sep + mime_file_name, 'wt')
            file_obj.write(mime_file_content)
            file_obj.close()
            xml_util.compose(file_name)




# ROUTE协议处理
def acquire_route_sls(broadcastSvcSignaling, pcap_result, service_dir_name):
    # 为每个服务过滤相应的pcap数据包
    filtered_pcap_result = pcap_filter.pcap_packet_filter(pcap_result, broadcastSvcSignaling.slsDestinationIpAddress, broadcastSvcSignaling.slsDestinationUdpPort)
    filtered_pcap_packet = filtered_pcap_result[1]
    # 过滤TSI
    sls_udp_packet_list = set()
    for pcap_packet in filtered_pcap_packet:
        udp_data = cut_header.cut_udp_header(pcap_packet)
        raw_tsi = udp_data[8:12]
        tsi = tsi_to_value(raw_tsi)
        if(tsi == 0):
            sls_udp_packet_list.add(udp_data)
    sls_entire_data = route_packaging.sls_packaging(sls_udp_packet_list)
    # 解析MIME内容数据
    mime_content_dict = mime_parser.parse(StringIO(sls_entire_data))
    save_mime_content_file(mime_content_dict, service_dir_name)