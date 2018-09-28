import shutil
import os

"""从文件描述符存储xml文件，以type和time_stamp为其命名
"""

def save_xml_file(file, type, time_stamp):
    type_path = 'lls_content' + os.sep + type
    if(not os.path.exists(type_path)):
        os.makedirs(type_path)
    decompress_file_name = ('%s_%d.xml' %(type, time_stamp))
    decompress_file = open(type_path + os.sep + decompress_file_name, 'wb')
    shutil.copyfileobj(file, decompress_file)
    decompress_file.close()
    return decompress_file_name

