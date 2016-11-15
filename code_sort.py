#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: anchen
# @Date:   2016-08-23 17:24:54
# @Last Modified by:   anchen
# @Last Modified time: 2016-11-12 21:08:46
import os
import re
import sys
import time
reload(sys)
sys.setdefaultencoding('utf-8')

class Analyze(object):
    """docstring for Analyze"""
    def __init__(self, FilePath, apk_md5, temp_out_file):
        self.FilePath = FilePath 
        self.apk_md5 = apk_md5
        self.key = ''
        self.filepath = ''
        self.line_index = ''
        self.code_content = ''
        self.print_flag = 0
        self.temp_content = ''
        self.temp_out_file = temp_out_file

    def clear(self):
        self.filepath = ''
        self.line_index = ''
        self.code_content = ''

    def enablePrint(self):
        self.print_flag = 1

    def getRegularExpression(self):
        expr_dict={}
        with open('setting/api_map.ini','r') as f:
            for i in f:
                ret=i.split('\n')
                ret1=ret[0].split('=')
                expr_dict[ret1[0]] = ret1[1]
        expr_list=sorted(expr_dict.iteritems(),key = lambda asd:asd[0],reverse = False)
        return expr_list

    def update_outdate(self):
        out = self.apk_md5 + '|' + self.key + '|' + self.filepath + '|' + self.line_index + '|' + self.code_content + '\n'
        self.temp_content += out 

    def out_temp_file(self):
        with open(self.temp_out_file,'w+') as f:
            f.write(self.temp_content)

    def GetFilePathList(self, rootDir):
        FilePathList=[]
        for root,dirs,files in os.walk(rootDir):
            for filespath in files:
                FilePathList.append(os.path.join(root,filespath))
        return FilePathList

    def GetCodeBlockFromJavaSouce(self, Context, StringToFind):
        pattern = re.compile(StringToFind)  
        results = pattern.findall(Context) 
        return results
        
    def FindTarStringLocationInFile(self, file, TarString):
        line_num = 0
        ContextToSave = ''
        with open(file,'r') as f:
            for line in f:
                line_num+=1
                ret = self.GetCodeBlockFromJavaSouce(line,TarString)
                if ret and "CONTACT javamail@sun.com" not in line and 'android' not in file:
                    ContextToSave+= file +':' + str(line_num)+'\r'+line+'\r'
                    self.filepath = file
                    self.line_index = str(line_num)
                    self.code_content = line.strip()
                    break 
            if self.print_flag:
                print ContextToSave.strip()

    def FindTarString(self,packagePath,calledFunc):
        list=self.GetFilePathList(self.FilePath)
        for l in list:
            if 'android' not in l and 'javax' not in l and 'res' not in l and '.java' in l:
                with open(l,'r') as f:
                    Context=f.read()
                ret=self.GetCodeBlockFromJavaSouce(Context,calledFunc)
                if ret:
                    if packagePath == 'None':
                        self.FindTarStringLocationInFile(l,calledFunc)
                        break
                    elif self.GetCodeBlockFromJavaSouce(Context,packagePath):
                        self.FindTarStringLocationInFile(l,calledFunc)
                        break 

    def run(self):
        expr_list = self.getRegularExpression()
        for l in expr_list:
            self.key = l[0]
            calledFunc = l[1].split('|')[0]
            packagePath = l[1].split('|')[1]
            self.FindTarString(packagePath,calledFunc)
            if self.code_content is not '':
                self.update_outdate()
            self.clear()
        self.out_temp_file()

    def clear_file(self,path):
        with open(path,'w+') as f:
            f.write('')

    def do_run(self):
        self.clear_file(self.temp_out_file)
        path_exits = os.path.exists(self.FilePath)
        if path_exits:
            self.run()
        else:
            self.clear_file(self.temp_out_file)