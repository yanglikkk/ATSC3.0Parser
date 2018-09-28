from pcap_preprocess import pcap_filter, cut_header
from LLS import lls_parser
from atsc_utils import decompress_util, file_util, xml_util
from SLT import slt_parser
from ROUTE import route_packaging, mime_parser, route_manager
from MMTP import mmtp_packet, mmtp_manager

import pcap
from io import BytesIO, StringIO
import os, platform

# 获取当前python版本号，选择合适的ip对比方法
python_major_num = int(platform.python_version().split('.')[0])

# 通过slt信息抓取sls。
# 解析已经传入的slt文件，并依据已经存在服务的sls来过滤重复信息，
# 根据slt指定的ip和端口，筛选pcap数据，分离不同传输对象的UDP包，
# 最后拼接在一起，经由MIME解析，分别存放xml文件。
def catch_sls_with_slt_info(pcap_result, slt_obj):
    saved_sls_dir_list = []
    # sls信息重复判断
    for service in slt_obj.service:
        # 暂时过滤category不为1的sls
        if(int(service.serviceCategory) != slt_parser.CATEGORY_VALUE_LINEAR_AV_SERVICE):
            continue
        if(not hasattr(service, slt_parser.BROADCAST_SVC_SIGNALING_NAME)):
            continue
        broadcastSvcSignaling = service.broadcastSvcSignaling
        # 略过已经存在的sls
        if(slt_parser.is_sls_exist(service, broadcastSvcSignaling.slsProtocol)):
            continue
        # 根据不同的协议类型，选择不同的解析方法
        if(broadcastSvcSignaling.slsProtocol == slt_parser.SLS_PROTOCOL_TYPE_ROUTE):
            service_dir_name = slt_parser.ROUTE_DIR + os.sep + service.serviceCategory + '_' + service.shortServiceName
            route_manager.acquire_route_sls(broadcastSvcSignaling, pcap_result, service_dir_name)
        elif(broadcastSvcSignaling.slsProtocol == slt_parser.SLS_PROTOCOL_TYPE_MMTP):
            service_dir_name = slt_parser.MMPT_DIR + os.sep + service.serviceCategory + '_' + service.shortServiceName
            mmtp_manager.acquire_MMTP_sls(broadcastSvcSignaling, pcap_result, service_dir_name)
        else:
            return
        saved_sls_dir_list.append(service_dir_name)
    # 返回sls文件目录列表
    return saved_sls_dir_list

# 从pcap数据中获取存储slt文件。
# 解析流中LLS信息，解压获取slt文件，并完成xml文件重排.
def acquire_slt_in_pcap(pcap_result):
    # 获取过滤后的pcap包，得到udp数据包集
    packet_set = pcap_filter.pcap_packet_filter(pcap_result, ip_string)
    for pcap_time, udp_packet in zip(packet_set[0], packet_set[1]):
        # udp数据包去头处理
        udp_data = cut_header.cut_udp_header(udp_packet)
        # udp_data数据解析为lls_table 
        lls_table = lls_parser.lls_header_parser(udp_data)
        # 解压获取lls_table内data的xml数据
        decompress_buffer = decompress_util.decompress_gzip(BytesIO(lls_table.data))
        lls_table_type = ''
        # 根据lls类型，指定对应存储的子目录
        if(lls_table.lls_table_id == lls_parser.SLT_TYPE_VALUE):
            lls_table_type = lls_parser.SLT_TYPE_NAME
        elif (lls_table.lls_table_id == lls_parser.RRT_TYPE_VALUE):
            lls_table_type = lls_parser.RRT_TYPE_NAME
        elif (lls_table.lls_table_id == lls_parser.SYSTEM_TIME_TYPE_VALUE):
            lls_table_type = lls_parser.SYSTEM_TIME_TYPE_NAME
        elif (lls_table.lls_table_id == lls_parser.AEAT_TYPE_VALUE):
            lls_table_type = lls_parser.AEAT_TYPE_NAME
        else:
            print('lls_parser: invalid udp packet, can\'t resolved')
            continue
        # 根据类型、时间，命名保存xml文件
        decompress_file_name = file_util.save_xml_file(decompress_buffer, lls_table_type, pcap_time)
        # print('lls_parser: decompressed file name: %s' %decompress_file_name)
        # slt表格式重排
        xml_util.compose('lls_content' + os.sep + lls_table_type + os.sep + decompress_file_name)

# start point
# 指定输入的pcap文件和作为过滤条件的IP地址
ROUTE_PCAP_FILE_NAME = 'ALP-sbs-2.pcap'
MMTP_PCAP_FILE_NAME = '4K_Korea.pcap'
ip_string = '224.0.23.60'
# pcap_file_name = MMTP_PCAP_FILE_NAME
pcap_file_name = ROUTE_PCAP_FILE_NAME
pcap_result = pcap.pcap(pcap_file_name)

# 解析LLS表
acquire_slt_in_pcap(pcap_result)

# 遍历所有SLT文件，并解析
for file_name in os.listdir(lls_parser.SLT_DIR):
    pcap_result = pcap.pcap(pcap_file_name)
    # 合成文件路径
    file_path = lls_parser.SLT_DIR + os.sep + file_name
    if(not os.path.isdir(file_path)):
        # 解析SLT，获取服务信息
        slt_obj = slt_parser.parserXml(file_path)
        # 根据slt信息获取sls文件，得到存储的sls文件目录
        saved_sls_dir_list = catch_sls_with_slt_info(pcap_result, slt_obj)
        if(len(saved_sls_dir_list) != 0):
            print(saved_sls_dir_list)