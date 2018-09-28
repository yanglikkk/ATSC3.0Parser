""" MMTP packet header """
# V(version): 2 bits
# C(packet_counter_flag): 1 bit
# FEC(FEC_type): 2 bits
# X(extension): 1 bit
# R(RAP_flag): 1 bit
# Q（QoS_classifier_flag): 1 bit

# 包头字段掩码
V_MASK = 0b11000000
C_MASK = 0B00100000
TYPE_MASK = 0B00001111

# 包头字段常量
V_FOR_QOS_SUPPORT = 0b01000000
C_ENABLED = 0B00100000
TYPE_SINALLING_MESSAGE = 0B00000010
# mmpt包头实体类
class mmpt_packet_header:
    def __init__(self, header):
        self.header = header
        self.mmtp_base_message = mmtp_base_message(header[20:])
    def is_v_for_qos_support(self):
        return V_FOR_QOS_SUPPORT == (self.header[0] & V_MASK)

    def is_c_enabled(self):
        return C_ENABLED == (self.header[0] & C_MASK)

    def is_type_sinalling_message(self):
        return TYPE_SINALLING_MESSAGE == (self.header[1] & TYPE_MASK)
# bytes数组转int数值的工具方法
def bytes_to_int(input_bytes):
    if(len(input_bytes) > 4):
        return
    return int.from_bytes(input_bytes, 'big')
""" MMTP payload """
# mmtp_base_message，mmtp消息的基类
class mmtp_base_message:
    def __init__(self, message):
        self.message = message
        self.message_id = bytes_to_int(message[0:2])
        self.base_version = message[2]
    def is_message_id_of_mmt_atsc_message(self):
        return self.message_id == 0x8100
    def is_message_id_of_mpt_message(self):
        return self.message_id >= 0x0011 and self.message_id <= 0x0020
# mmt_atsc3_message对应的实体类
class mmt_atsc3_message(mmtp_base_message):
    def __init__(self, message):
        super().__init__(message)
        self.length = bytes_to_int(message[3:7])
        self.service_id = bytes_to_int(message[7:9])
        self.message_type = bytes_to_int(message[9:11])
        self.message_version = message[11]
        self.message_compression = message[12]
        self.uri_length = message[13]
        self.uri_base_offset = 14
        self.uri = self.message[self.uri_base_offset:self.uri_base_offset + self.uri_length].decode('utf-8')
    # 判断是否为usbd类型的message
    def is_message_type_usbd(self):
        return self.message_type == 0x0001
    # 获取信息内容
    def get_message_content(self):
        if(not hasattr(self, 'message_content_length')):
            self.message_content_length = bytes_to_int(self.message[self.uri_base_offset + self.uri_length:self.uri_base_offset + self.uri_length + 4])
            self.message_content_base = self.uri_base_offset + self.uri_length + 4
        return self.message[self.message_content_base:self.message_content_base + self.message_content_length]
# mpt_message对应的实体类
class mpt_message(mmtp_base_message):
    def __init__(self, message):
        super().__init__(message)
        self.length = bytes_to_int(message[3:5])
        # 解析mp_table
        self.mp_table = mp_table(message[5:])
# mp_table对应的实体类
class mp_table():
    def __init__(self, mp_table_message):
        self.message = mp_table_message
        self.table_id = mp_table_message[0]
        self.version = mp_table_message[1]
        self.length = bytes_to_int(mp_table_message[2:4])
        self.reserved_and_mp_table_mode = mp_table_message[4]
        current_offset = 5
        if(self.is_start_or_end_mp_table_id()):
            # 头尾id独有的字段解析
            mmt_packet_id_length = self.message[current_offset]
            current_offset += 1
            self.mmt_packet_id = self.get_mmt_packet_id(mmt_packet_id_length, current_offset)
            current_offset += mmt_packet_id_length
            mp_table_descriptors_length = bytes_to_int(self.message[current_offset:current_offset + 2])
            current_offset += 2
            self.mp_table_descriptors = self.get_mp_table_descriptors(mp_table_descriptors_length, current_offset)
            current_offset += mp_table_descriptors_length
        # 获取assets数据
        self.number_of_assets = self.message[current_offset]
        current_offset += 1
        self.assets = self.get_assets(self.number_of_assets, current_offset)
    # 判断是否头尾table_id
    def is_start_or_end_mp_table_id(self):
        return self.table_id == 0x11 or self.table_id == 0x20
    # 获取mmt_packet_id
    def get_mmt_packet_id(self, mmt_packet_id_length, current_offset):
        if(mmt_packet_id_length == 0):
            return ''
        else:
            return self.message[current_offset:current_offset + mmt_packet_id_length]
    # 获取mp_table_descriptors
    def get_mp_table_descriptors(self, mp_table_descriptors_length, current_offset):
        if(mp_table_descriptors_length == 0):
            return ''
        else:
            return self.message[current_offset:current_offset + mp_table_descriptors_length]
    # 获取assets
    def get_assets(self, number_of_assets, base_offset):
        count = 0
        current_offset = base_offset
        assets_list = []
        while(count < number_of_assets):
            # 创建asset实例
            a_asset = asset()
            # 获取identifier_mapping
            a_asset.identifier_mapping = identifier_mapping(self.message, current_offset)
            current_offset += a_asset.identifier_mapping.added_offset
            a_asset.asset_type = self.message[current_offset:current_offset + 4]
            current_offset += 4
            a_asset.daf_and_res_and_acr_flag = self.message[current_offset]
            current_offset += 1
            if(a_asset.daf_and_res_and_acr_flag & 0x01 == 1):
                # asset_clock_relation_flag == 1
                a_asset.asset_clock_relation_id = self.message[current_offset]
                current_offset += 1
                a_asset.res_and_asset_timescale_flag = self.message[current_offset]
                current_offset += 1
                if(a_asset.res_and_asset_timescale_flag & 0x01 == 1):
                    a_asset.asset_timescale = bytes_to_int(self.message[current_offset:current_offset + 4])
                    current_offset += 4
            # 获取location数据
            a_asset.location_count = self.message[current_offset]
            current_offset += 1
            a_asset.location_infos, add_offset = self.get_asset_location_infos(a_asset.location_count, current_offset)
            current_offset += add_offset
            # 获取asset_descriptors
            a_asset.asset_descriptors_length = bytes_to_int(self.message[current_offset:current_offset + 2])
            current_offset += 2
            a_asset.asset_descriptors = self.message[current_offset:current_offset + a_asset.asset_descriptors_length]
            current_offset += a_asset.asset_descriptors_length
            assets_list.append(a_asset)
            count += 1
        return assets_list
    # 获取asset_location_infos
    def get_asset_location_infos(self, location_count, base_offset):
        current_offset = base_offset
        count = 0
        location_info_list = []
        while(count < location_count):
            location_info = mmt_general_location_info(self.message, current_offset)
            location_info_list.append(location_info)
            current_offset += location_info.added_offset
            count += 1
        return location_info_list, current_offset - base_offset
# asset对应的实体类，属性与类型相关，动态填充
class asset():
    pass
# identifier_mapping对应的实体类
class identifier_mapping():
    def __init__(self, message, base_offset):
        current_offset = base_offset
        self.message = message
        self.identifier_type = message[current_offset]
        current_offset += 1
        # 根据identifier_type获取相应的字段
        if(self.identifier_type == 0x00):
            self.asset_id, added_offset = self.get_asset_id(current_offset)
            current_offset += added_offset
        elif(self.identifier_type == 0x01):
            self.url_count = bytes_to_int(message[1:3])
            print('identifier_mapping: identifier_type = 0x01')
        elif(self.identifier_type == 0x02):
            print('identifier_mapping: identifier_type = 0x02')
            pass
        elif(self.identifier_type == 0x03):
            print('identifier_mapping: identifier_type = 0x03')
            pass
        else:
            print('identifier_mapping: identifier_type = %d' %self.identifier_type)
            pass
        self.added_offset = current_offset - base_offset
    # identifier_type = 0x00时，获取asset_id
    def get_asset_id(self, base_offset):
        current_offset = base_offset
        self.asset_id_scheme = bytes_to_int(self.message[current_offset:current_offset + 4])
        current_offset += 4
        self.asset_id_length = bytes_to_int(self.message[current_offset:current_offset + 4])
        current_offset += 4
        return self.message[current_offset:current_offset + self.asset_id_length], current_offset + self.asset_id_length - base_offset
# mmt_general_location_info对应的实体类
class mmt_general_location_info():
    def __init__(self, message, base_offset):
        current_offset = base_offset
        self.location_type = message[current_offset]
        current_offset += 1
        # 根据location_type获取相应字段
        if(self.location_type == 0x00):
            self.packet_id = bytes_to_int(message[current_offset:current_offset + 2])
            current_offset += 2
        else:
            print('mmt_general_location_info: other location type = %d' %self.location_type)
        self.added_offset = current_offset - base_offset