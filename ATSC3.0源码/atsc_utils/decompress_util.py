# -*- coding: iso-8859-15 -*-
import gzip

"""解压缩文件对象，fileobject内存中的
"""
def decompress_gzip(fileobject):
    compressLevel = 9
    mode = 'rb'
    return gzip.GzipFile(None , mode, compressLevel, fileobject)
