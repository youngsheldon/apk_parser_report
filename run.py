#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: anchen
# @Date:   2016-11-14 09:06:43
# @Last Modified by:   anchen
# @Last Modified time: 2016-11-16 10:50:18
import os
import sys 
import functools
from file_hash import *
from report_data_sort import * 
from virus_tell import VirusTell 
from Mylog import Mylog

apk_path = sys.argv[1]
source_path = sys.argv[2]

file_size = get_file_size(apk_path)
apk_name = get_filename(apk_path)
apk_sha1 = check_hash(apk_path,'sha1')
mylog = Mylog('data/log.txt').getObject()

# @log_time(apk_sha1,17)
def decode_apk():
    arg = source_path + ' ' + apk_path
    os.system('JAVA_OPTS=\"-Xmx4G\" jadx -j 1 -d ' + arg)

# @log_time(apk_sha1,18)
def code_parser():
    ret = os.path.exists(source_path)
    if ret:
        run_code_parser(source_path,apk_sha1)
        return True
    else:
        return False 

def check_sha1(sha1):
    with open('data/sha1.txt','r') as f:
        content = f.read()
        if sha1 in content:
            return True 
        else:
            return False 

def save_apk_sha1(sha1):
    out = sha1 + '\n'
    with open('data/sha1.txt','a+') as f:
        f.write(out)


def upload_data(table,data):
    out = 'bcp SMMC7DB..' + table + ' in ' + data + ' -Usa -P -SSMMC5000 -c -t\'|\' -r\'\\n\'  -Y'
    os.system(out)

def upload_all_data():
    path = apk_sha1 + '/'
    upload_data('ywc_apk_recv_serv','data/' + path + 'recv_serv.txt')
    upload_data('ywc_apk_code_block','data/' + path + 'codeblock.txt')
    upload_data('ywc_apk_basic_info','data/' + path +'basic_info.txt')
    upload_data('ywc_apk_act_permis','data/' + path +'permis_act.txt')
    upload_data('ywc_apk_res','data/' + path +'res.txt')

def run_virus_tell():
    tell_result = 0 
    obj = VirusTell(apk_sha1)
    v = obj.virus_tell()
    if v >= 0 and v <= 50:
        tell_result = 0
    elif v > 50 and v <= 70:
        tell_result = 1
    else:
        tell_result = 2 
    out = apk_sha1 + '|' + '7' + '|' + str(v) + '\n'
    out += apk_sha1 + '|' + '8' + '|' + str(tell_result) + '\n'
    path = 'data/' + apk_sha1 + '/' + 'basic_info.txt'
    with open(path,'a+') as f:
        f.write(out)

def mkdir_for_data_file(sha1):
    out = 'data/' + sha1
    os.makedirs(out)

@log_time(apk_sha1,9)
def apk_analyze_run():
    if file_size > 800000:
        print 'file_size is over 800M'
        return False 
    else:
        if check_sha1(apk_sha1):
            print 'this apk has been handled'
            return False
        else:
            save_apk_sha1(apk_sha1)
            mkdir_for_data_file(apk_sha1)
            mylog.info('[' + apk_sha1 + ':begin to decode apk]')
            decode_apk()
            try:
                mylog.info('[' + apk_sha1 + ':begin to parser xml]')
                ret = run_xml_parser(source_path,apk_sha1)
                if ret:
                    run_baseinfo_parser(apk_path,source_path,apk_sha1)
                    mylog.info('[' + apk_sha1 + ':begin to parser code]')
                    ret2 = code_parser()
                    if ret2:
                        mylog.info('[' + apk_sha1 + ':begin to tell apk]')
                        run_virus_tell()
                        return True 
                    else:
                        return False 
                else:
                    return False 
            except Exception, e:
                mylog.exception(apk_sha1)
                os._exit(0)

ret = apk_analyze_run()
if ret:
    mylog.info('[' + apk_sha1 + ':begin to upload data to database]')
    upload_all_data()
    mylog.info('[' +apk_sha1 + '----------finish---------]')