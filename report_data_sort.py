#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: anchen
# @Date:   2016-11-11 16:42:53
# @Last Modified by:   anchen
# @Last Modified time: 2016-11-16 12:01:29
import os 
from xml_parser import XmlParser
from file_hash import *
from res_file_find import *
from code_sort import Analyze
    
def write_to_file(path,data):
    with open(path,'a+') as f:
        f.write(data)

def list_type_data_out(path,data_type,in_list,md5):
    out = ''
    if len(in_list) == 0:
        out += md5 + '|' + str(data_type) + '|' + '0' + '\n'
    else:
        for item in in_list:
            out += md5 + '|' + str(data_type) + '|' + item + '\n'
    write_to_file(path,out)

def dict_type_data_out(path,data_type,in_dict,md5):
    out = ''
    for k,v in in_dict.items():
        if v[0] == None:
            v[0] = '0'
        if v[1] is not None:
            for item in v[1]:
                out += md5 + '|' + str(data_type) + '|' + k + '|' + v[0] + '|' + item +'\n'
        else:
            out += md5 + '|' + str(data_type) + '|' + k + '|' + v[0] + '|' + '0' +'\n'
    write_to_file(path,out)

def single_type_data_out(path,data_type,in_data,md5):
    out = ''
    out += md5 + '|' + str(data_type) + '|' + str(in_data) + '\n'
    write_to_file(path,out)

def utf_to_gbk(path):
    with open(path,'r') as f:
        content = f.read()
    with open(path,'w') as f:
        src = content.decode("utf8").encode("gbk") 
        f.write(src)

def run_xml_parser(apk_source_path,md5):
    xml_path = apk_source_path + 'AndroidManifest.xml'
    ret = os.path.exists(xml_path)
    if ret:
        path = md5 + '/'
        # 解析权限和action
        obj = XmlParser(xml_path)
        action_list = obj.praserPermissionOrAction('action')
        permis_list = obj.praserPermissionOrAction('uses-permission')
        list_type_data_out('data/' + path + 'permis_act.txt',1,action_list,md5)
        list_type_data_out('data/' + path + 'permis_act.txt',2,permis_list,md5)
        #解析监听器和服务
        receiver_out_dict = obj.parserReceiver()
        service_out_dict = obj.parserService()
        dict_type_data_out('data/' + path + 'recv_serv.txt',1,receiver_out_dict,md5)
        dict_type_data_out('data/' + path + 'recv_serv.txt',2,service_out_dict,md5)
        #解析sdk版本
        minsdk_v,tarsdk_v = obj.parserSdkVersion()
        single_type_data_out('data/' + path + 'basic_info.txt',10,minsdk_v,md5)
        single_type_data_out('data/' + path + 'basic_info.txt',11,tarsdk_v,md5)
        return True 
    else:
        return False 

def run_baseinfo_parser(apk_path,apk_source_path,md5_v):
    path = md5_v + '/'
    md5 = check_hash(apk_path,'md5')
    sha1 = check_hash(apk_path,'sha1')
    sha256 = check_hash(apk_path,'sha256')
    sha512 = check_hash(apk_path,'sha512')
    file_size = get_file_size(apk_path)
    file_name = get_filename(apk_path)
    picture_list = collect_picture(apk_source_path)
    data_list = collect_data(apk_source_path)
    inf_list = collect_inf(apk_source_path)
    bin_list = collect_inf(apk_source_path)
    
    single_type_data_out('data/' + path + 'basic_info.txt',1,file_name,md5_v)
    single_type_data_out('data/' + path + 'basic_info.txt',2,file_size,md5_v)
    single_type_data_out('data/' + path + 'basic_info.txt',3,md5,md5_v)
    single_type_data_out('data/' + path + 'basic_info.txt',4,sha1,md5_v)
    single_type_data_out('data/' + path + 'basic_info.txt',5,sha256,md5_v)
    single_type_data_out('data/' + path + 'basic_info.txt',6,sha512,md5_v)

    list_type_data_out('data/' + path + 'res.txt',4,picture_list,md5_v)
    list_type_data_out('data/' + path + 'res.txt',3,data_list,md5_v)
    list_type_data_out('data/' + path + 'res.txt',1,inf_list,md5_v)
    list_type_data_out('data/' + path + 'res.txt',2,bin_list,md5_v)

def run_code_parser(apk_source_path,apk_md5):
    temp_out_file = 'data/' + apk_md5 + '/' + 'codeblock.txt'
    obj = Analyze(apk_source_path,apk_md5,temp_out_file)
    obj.enablePrint()
    obj.do_run()
    utf_to_gbk(temp_out_file)