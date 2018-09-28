import os
from pcap_preprocess import cut_header
from io import BytesIO
from atsc_utils import decompress_util, file_util
# lls类型常量
SLT_TYPE_VALUE = 1
RRT_TYPE_VALUE = 2
SYSTEM_TIME_TYPE_VALUE = 3
AEAT_TYPE_VALUE = 4
# lls类型名
SLT_TYPE_NAME = 'SLT'
RRT_TYPE_NAME = 'RRT'
SYSTEM_TIME_TYPE_NAME = 'SystemTime'
AEAT_TYPE_NAME = 'AEAT'
# 文件目录常量
LLS_CONTENT_DIR = 'lls_content'
SLT_DIR = LLS_CONTENT_DIR + os.sep + SLT_TYPE_NAME
SYSTEM_TIME_DIR = LLS_CONTENT_DIR + os.sep + SYSTEM_TIME_TYPE_NAME
RRT_DIR = LLS_CONTENT_DIR + os.sep + RRT_TYPE_NAME
AEAT_DIR = LLS_CONTENT_DIR + os.sep + AEAT_TYPE_NAME
# lls实体类
class Lls_table:
    lls_table_id = 0
    lls_group_id = 0
    lls_group_count_minus1 = 0
    lls_table_version = 0
    data = 0

# 传入参数data为udp数据部分，解析lls_table表，返回参数lls表信息
def lls_header_parser(data):
    lls_table = Lls_table()
    lls_table.lls_table_id = data[0]
    if lls_table.lls_table_id == SLT_TYPE_VALUE:
        pass
        # print("header_parser: parsing SLT")
    elif lls_table.lls_table_id == RRT_TYPE_VALUE:
        pass
        # print("header_parser: parsing RRT")
    elif lls_table.lls_table_id == SYSTEM_TIME_TYPE_VALUE:
        pass
        # print("header_parser: parsing SystemTime")
    elif lls_table.lls_table_id == AEAT_TYPE_VALUE:
        pass
        # print ("header_parser: parsing AEAT")
    lls_table.lls_group_id = data[1]
    lls_table.group_count_minus1 = data[2]
    lls_table.lls_table_version = data[3]
    lls_table.data = data[4:]
    return lls_table
