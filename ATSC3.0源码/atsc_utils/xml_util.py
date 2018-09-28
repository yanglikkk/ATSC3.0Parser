from xml.dom import minidom
from codecs import open
import os
from atsc_utils import file_util
VALID_XML_EXTENSION = '.xml'

# xml文件重排版
def compose(compose_file_name):
    #传入文件名的参数，分离文件名和拓展名
    (shotname,extension)=os.path.splitext(compose_file_name)
    if(extension != VALID_XML_EXTENSION):
        print('xml_util: invalid xml file name')
        return
    doc = minidom.parse(shotname + VALID_XML_EXTENSION)
    out_put_file = open(shotname + VALID_XML_EXTENSION, 'w', encoding='utf-8')
    # addindent表示子元素缩进，newl='\n'表示元素间换行，encoding='utf-8'表示生成的xml的编码格式（<?xml version="1.0" encoding="utf-8"?>）
    doc.writexml(out_put_file, addindent='  ', newl='\n', encoding='utf-8')
    return compose_file_name