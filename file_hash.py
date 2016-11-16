#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: anchen
# @Date:   2016-11-10 09:20:32
# @Last Modified by:   anchen
# @Last Modified time: 2016-11-16 14:54:36
import hashlib
import os,sys
import functools
import time
from Mylog import Mylog 
from os.path import join, getsize

def check_hash(filepath,type):
    with open(filepath,'rb') as f:
        if type == 'md5':
            obj = hashlib.md5()
        elif type == 'sha1':
            obj = hashlib.sha1()
        elif type == 'sha256':
            obj = hashlib.sha256()
        else:
            obj = hashlib.sha512()
        obj.update(f.read())
        hash = obj.hexdigest()
        return hash    

def get_file_size(path):
    return getsize(path)/1024.0 

def get_filename(path):
    return path.split('/')[-1].split('.')[0]

def get_file_num(rootDir):
    file_path_list=[]
    for root,dirs,files in os.walk(rootDir):
        for filespath in files:
            file_path_list.append(os.path.join(root,filespath))
    return len(file_path_list)

def log_time(md5,index):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            t1 = time.time()
            ret = func(*args,**kw)
            t2 = time.time()
            with open('data/'+ md5 + '/basic_info.txt','a+') as f:
                out = md5 + '|' + str(index) + '|' + str(t2-t1) + '\n'
                f.write(out)
            return ret 
        return wrapper
    return decorator

def out_report(md5,index,value):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            out = md5 + '|' + str(index) + '|' + str(value) + '\n'
            with open('data/' + md5 + '/basic_info.txt','r') as f:
                f.write(out)
            return func(*args,**kw)
        return wrapper
    return decorator