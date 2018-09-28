import xml.dom.minidom
import os
# sls相关的文件目录常量
SLS_DIR = 'sls_content'
ROUTE_DIR = SLS_DIR + os.sep + 'route'
MMPT_DIR = SLS_DIR + os.sep + 'mmtp'
# 需要用到的SLT字段常量值
CATEGORY_VALUE_LINEAR_AV_SERVICE = 1
SERVICE_CATEGORY_NAME = 'serviceCategory'
BROADCAST_SVC_SIGNALING_NAME = 'broadcastSvcSignaling'
SLS_PROTOCOL_TYPE_ROUTE = 1
SLS_PROTOCOL_TYPE_MMTP = 2
# 去重判断，检查当前SLT对应的服务是否已经抓取过引导信令
def is_sls_exist(slt_obj, sls_protocol_type):
    if(sls_protocol_type == SLS_PROTOCOL_TYPE_ROUTE):
        check_dir = ROUTE_DIR
    elif(sls_protocol_type == SLS_PROTOCOL_TYPE_MMTP):
        check_dir = MMPT_DIR
    else:
        return
    if(not os.path.exists(check_dir)):
        return False
    for file_name in os.listdir(check_dir):
        if(os.path.isdir(check_dir + os.sep + file_name)):
            name_info = file_name.split('_')
            if(len(name_info) == 2):
                if(name_info[0] == slt_obj.serviceCategory and name_info[1] == slt_obj.shortServiceName):
                    return True
                else:
                    continue
            else:
                continue
        else:
            continue
    return False
# slt表实体类
class Slt:
    def __init__(self, service):
        self.service = service
# service标签实体类
class Service:
    def __init__(self,serviceId,serviceCategory,shortServiceName,broadcastSvcSignaling):
        self.serviceId = serviceId
        self.serviceCategory = serviceCategory
        self.shortServiceName = shortServiceName
        self.broadcastSvcSignaling = broadcastSvcSignaling
# BroadcastSvcSignaling标签实体类
class BroadcastSvcSignaling:
    def __init__(self,slsDestinationIpAddress,slsDestinationUdpPort):
        self.slsDestinationIpAddress = slsDestinationIpAddress
        self.slsDestinationUdpPort = slsDestinationUdpPort
# 解析slt的XML文件
def parserXml(fileName):
    dom = xml.dom.minidom.parse(fileName)
    root = dom.documentElement
    # 依据slt的字段结构读入需要用到的属性
    serv = root.getElementsByTagName('Service')
    service_list = []
    for i in serv:
        serviceId =i.getAttribute('serviceId')
        serviceCategory = i.getAttribute('serviceCategory')
        shortServiceName = i.getAttribute('shortServiceName')
        if(len(i.getElementsByTagName('BroadcastSvcSignaling')) == 0):
            service = Service(serviceId, serviceCategory, shortServiceName, None)
            service_list.append(service)
        else:
            broadcastSvcSignaling = i.getElementsByTagName('BroadcastSvcSignaling')
            slsDestinationIpAddress = broadcastSvcSignaling[0].getAttribute('slsDestinationIpAddress')
            slsDestinationUdpPort = broadcastSvcSignaling[0].getAttribute('slsDestinationUdpPort')
            broadcast = BroadcastSvcSignaling(slsDestinationIpAddress,slsDestinationUdpPort)
            broadcast.slsProtocol = int(broadcastSvcSignaling[0].getAttribute('slsProtocol'))
            service = Service(serviceId,serviceCategory,shortServiceName,broadcast)
            service_list.append(service)
    slt = Slt(service_list)
    return slt