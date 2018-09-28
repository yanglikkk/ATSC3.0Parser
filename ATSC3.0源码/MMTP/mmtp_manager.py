from pcap_preprocess import pcap_filter, cut_header
from MMTP import mmtp_packet
from atsc_utils import xml_util
import os


# MMTP协议处理
def acquire_MMTP_sls(broadcastSvcSignaling, pcap_result, service_dir_name):
    filtered_pcap_result = pcap_filter.pcap_packet_filter(pcap_result, broadcastSvcSignaling.slsDestinationIpAddress, broadcastSvcSignaling.slsDestinationUdpPort)
    # MMTP packet 过滤
    for pcap_time, pcap_packet in zip(filtered_pcap_result[0], filtered_pcap_result[1]):
        udp_data = cut_header.cut_udp_header(pcap_packet)
        header = mmtp_packet.mmpt_packet_header(udp_data)
        if(header.is_v_for_qos_support() and header.is_c_enabled() and header.is_type_sinalling_message()):
            # mmtp包头符合要求
            message = header.mmtp_base_message
            if(message.is_message_id_of_mmt_atsc_message()):
                # mmt_atsc_message
                message = mmtp_packet.mmt_atsc3_message(message.message)
                if(message.is_message_type_usbd()):
                    # 处理message_type为usbd的message
                    uri = message.uri
                    if(uri == ''):
                        return
                    message_content = message.get_message_content()
                    if(not os.path.exists(service_dir_name)):
                        os.makedirs(service_dir_name)
                    save_mmt_atsc3_message(service_dir_name + os.sep + uri, message_content)
            elif(message.is_message_id_of_mpt_message()):
                # 解析mpt_message
                message = mmtp_packet.mpt_message(message.message)
                save_mpt_message(service_dir_name + os.sep + 'mpt_' + str(pcap_time), message)
                # print('\n')
# 存储mmt_atsc3_message
def save_mmt_atsc3_message(file_name, message_content):
    usbd_file = open(file_name, 'wb')
    usbd_file.write(message_content)
    usbd_file.close()
    xml_util.compose(file_name)

# 存储mpt_message信息
def save_mpt_message(file_name, message):
    # 判断输入信息是否为mpt_message类型实例
    if(isinstance(message, mmtp_packet.mpt_message)):
        out_put_file = open(file_name, 'wt')
        base_indent = ''
        # print('%smpt_message:' %base_indent)
        out_put_file.write(('%smpt_message:\n' %base_indent))
        base_indent = base_indent + '\t'
        # print('%smessage_id: %d' %(base_indent, message.message_id))
        out_put_file.write(('%smessage_id: %d\n' %(base_indent, message.message_id)))
        # print('%sversion: %d' %(base_indent, message.base_version))
        out_put_file.write(('%sversion: %d\n' %(base_indent, message.base_version)))
        # print('%slength: %d' %(base_indent, message.length))
        out_put_file.write(('%slength: %d\n' %(base_indent, message.length)))
        base_indent = base_indent + '\t'
        # print('%stable_id: %d' %(base_indent, message.mp_table.table_id))
        out_put_file.write(('%stable_id: %d\n' %(base_indent, message.mp_table.table_id)))
        # print('%sversion: %d' %(base_indent, message.mp_table.version))
        out_put_file.write(('%sversion: %d\n' %(base_indent, message.mp_table.version)))
        # print('%slength: %d' %(base_indent, message.mp_table.length))
        out_put_file.write(('%slength: %d\n' %(base_indent, message.mp_table.length)))
        # print('%sreserved: %d' %(base_indent, message.mp_table.reserved_and_mp_table_mode & 0b11111100))
        out_put_file.write(('%sreserved: %d\n' %(base_indent, message.mp_table.reserved_and_mp_table_mode & 0b11111100)))
        # print('%sMP_table_mode: %d' %(base_indent, message.mp_table.reserved_and_mp_table_mode & 0b00000011))
        out_put_file.write(('%sMP_table_mode: %d\n' %(base_indent, message.mp_table.reserved_and_mp_table_mode & 0b00000011)))
        # print('%slength: %d' %(base_indent, message.mp_table.length))
        out_put_file.write(('%slength: %d\n' %(base_indent, message.mp_table.length)))
        if(hasattr(message.mp_table, 'mmt_packet_id_length')):
            # print('%smmt_packet_id_length: %d' %(base_indent, message.mp_table.mmt_packet_id_length))
            out_put_file.write(('%smmt_packet_id_length: %d\n' %(base_indent, message.mp_table.mmt_packet_id_length)))
            # print('%smmt_packet_id: %s' %(base_indent, str(message.mp_table.mmt_packet_id)))
            out_put_file.write(('%smmt_packet_id: %s\n' %(base_indent, str(message.mp_table.mmt_packet_id))))
            # print('%smp_table_descriptors_length: %d' %(base_indent, message.mp_table.mp_table_descriptors_length))
            out_put_file.write(('%smp_table_descriptors_length: %d\n' %(base_indent, message.mp_table.mp_table_descriptors_length)))
            # print('%smp_table_descriptors: %s' %(base_indent, str(message.mp_table.mp_table_descriptors)))
            out_put_file.write(('%smp_table_descriptors: %s\n' %(base_indent, str(message.mp_table.mp_table_descriptors))))
        # print('%snumber_of_assets: %d' %(base_indent, message.mp_table.number_of_assets))
        out_put_file.write(('%snumber_of_assets: %d\n' %(base_indent, message.mp_table.number_of_assets)))
        count = 0
        for asset in message.mp_table.assets:
            # print('%sasset_%d:' %(base_indent, count))
            out_put_file.write(('%sasset_%d:\n' %(base_indent, count)))
            count += 1
            base_indent = base_indent + '\t'
            # print('%sidentifier_mapping:' %base_indent)
            out_put_file.write(('%sidentifier_mapping:\n' %base_indent))
            base_indent = base_indent + '\t'
            # print('%sidentifier_type: %d' %(base_indent, asset.identifier_mapping.identifier_type))
            out_put_file.write(('%sidentifier_type: %d\n' %(base_indent, asset.identifier_mapping.identifier_type)))
            if(asset.identifier_mapping.identifier_type == 0x00):
                # print('%sasset_id: %s' %(base_indent, str(asset.identifier_mapping.asset_id)))
                out_put_file.write(('%sasset_id: %s\n' %(base_indent, str(asset.identifier_mapping.asset_id))))
            base_indent = base_indent[:-1]
            # print('%sasset_type: %s' %(base_indent, asset.asset_type.decode('utf-8')))
            out_put_file.write(('%sasset_type: %s\n' %(base_indent, asset.asset_type.decode('utf-8'))))
            # print('%sreserved: %d' %(base_indent, asset.daf_and_res_and_acr_flag & 0b11111100))
            out_put_file.write(('%sreserved: %d\n' %(base_indent, asset.daf_and_res_and_acr_flag & 0b11111100)))
            # print('%sdefault_asset_flag: %d' %(base_indent, asset.daf_and_res_and_acr_flag & 0b00000010))
            out_put_file.write(('%sdefault_asset_flag: %d\n' %(base_indent, asset.daf_and_res_and_acr_flag & 0b00000010)))
            # print('%saseet_clock_relation_flag: %d' %(base_indent, asset.daf_and_res_and_acr_flag & 0b00000001))
            out_put_file.write(('%saseet_clock_relation_flag: %d\n' %(base_indent, asset.daf_and_res_and_acr_flag & 0b00000001)))
            if(asset.daf_and_res_and_acr_flag & 0b00000001 == 1):
                # print('%sasset_clock_relation_id: %d' %(base_indent, asset.asset_clock_relation_id))
                out_put_file.write(('%sasset_clock_relation_id: %d\n' %(base_indent, asset.asset_clock_relation_id)))
                # print('%sreserved: %d' %(base_indent, asset.res_and_asset_timescale_flag & 0b11111110))
                out_put_file.write(('%sreserved: %d\n' %(base_indent, asset.res_and_asset_timescale_flag & 0b11111110)))
                # print('%sasset_timescale_flag: %d' %(base_indent, asset.res_and_asset_timescale_flag & 0b00000001))
                out_put_file.write(('%sasset_timescale_flag: %d\n' %(base_indent, asset.res_and_asset_timescale_flag & 0b00000001)))
                if(asset.res_and_asset_timescale_flag & 0b00000001 == 1):
                    # print('%sasset_timescale: %d' %(base_indent, asset.asset_timescale))
                    out_put_file.write(('%sasset_timescale: %d\n' %(base_indent, asset.asset_timescale)))
            # print('%slocation_count: %d' %(base_indent, asset.location_count))
            out_put_file.write(('%slocation_count: %d\n' %(base_indent, asset.location_count)))
            location_count = 0
            for location_info in asset.location_infos:
                # print('%slocation_info_%d:' %(base_indent, location_count))
                out_put_file.write(('%slocation_info_%d:\n' %(base_indent, location_count)))
                location_count += 1
                base_indent = base_indent + '\t'
                # print('%slocation_type: %d' %(base_indent, location_info.location_type))
                out_put_file.write(('%slocation_type: %d\n' %(base_indent, location_info.location_type)))
                if(location_info.location_type == 0x00):
                    # print('%spacket_id: %d' %(base_indent, location_info.packet_id))
                    out_put_file.write(('%spacket_id: %d\n' %(base_indent, location_info.packet_id)))
                base_indent = base_indent[:-1]
            # print('%sasset_descriptors_length: %d' %(base_indent, asset.asset_descriptors_length))
            out_put_file.write(('%sasset_descriptors_length: %d\n' %(base_indent, asset.asset_descriptors_length)))
            # print('%sasset_descriptors: %s' %(base_indent, str(asset.asset_descriptors)))
            out_put_file.write(('%sasset_descriptors: %s\n' %(base_indent, str(asset.asset_descriptors))))
            base_indent = base_indent[:-1]
        out_put_file.close()