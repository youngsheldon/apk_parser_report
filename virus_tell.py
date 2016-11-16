#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: anchen
# @Date:   2016-11-12 20:28:34
# @Last Modified by:   anchen
# @Last Modified time: 2016-11-16 16:46:27
import re 
import os 
from file_hash import * 
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

class VirusTell(object):
    """docstring for VirusTell"""
    def __init__(self,apk_md5):
        self.apk_md5 = apk_md5
        self.code_block = self.collect_code_block()
        self.first_code_valuate,self.second_code_valuate = self.get_code_valuate_setting()
        self.permis,self.action = self.collect_permis_act()
        self.recv_permis,self.recv_action,self.serv_permis,self.serv_action = self.collect_recv_serv()

    def collect_code_block(self):
        code_block = []
        with open('data/'+ self.apk_md5 + '/codeblock.txt','r') as f:
            for line in f:
                v = line.strip().split('|')[1]
                code_block.append(v)
            return code_block

    def collect_permis_act(self):
        with open('data/'+ self.apk_md5 +'/permis_act.txt','r') as f:
            permis = []
            action = []
            for line in f:
                v = line.strip().split('|')[2]
                index = line.strip().split('|')[1]
                if index == '19':
                    action.append(v)
                else:
                    permis.append(v)
            return permis,action 

    def collect_recv_serv(self):
        with open('data/'+ self.apk_md5 + '/recv_serv.txt','r') as f:
            recv_permis = []
            recv_action = []
            serv_permis = []
            serv_action = []
            for line in f:
                index = line.strip().split('|')[1]
                reques_permis = line.strip().split('|')[3]
                detect_action = line.strip().split('|')[4]
                if index == '12':
                    if reques_permis != '0':
                        recv_permis.append(reques_permis)
                    if detect_action != '0':
                        recv_action.append(detect_action)
                else:
                    if reques_permis != '0':
                        serv_permis.append(reques_permis)
                    if detect_action != '0':
                        serv_action.append(detect_action)
            return recv_permis,recv_action,serv_permis,serv_action

    def get_code_valuate_setting(self):
        with open('setting/valuate.ini','r') as f:
            first_code_valuate = []
            second_code_valuate = []
            for line in f:
                index = line.strip().split('|')[0]
                v = line.strip().split('|')[1]
                if index == '1':
                    first_code_valuate.append(v)
                elif index == '2':
                    second_code_valuate.append(v)
            return first_code_valuate,second_code_valuate

    def permis_set_list(self):
        permis_list = []
        with open('setting/permis_map.ini','r') as f:
            for line in f:
                v = line.strip().split('=')[1]
                if v not in permis_list:
                    permis_list.append(v)
            return permis_list

    def get_act_set_list(self):
        act_set_list = []
        with open('setting/valuate.ini','r') as f:
            for line in f:
                index = line.strip().split('|')[0]
                v = line.strip().split('|')[1]
                if index == '3':
                    act_set_list.append(v)
            return act_set_list

    def get_sum(self,to_cout,sum_list):
        couter = 0 
        for v in sum_list:
            if v in to_cout:
                couter += 1 
        return couter 

    def tell_code_block(self):
        first_code = []
        second_code = []
        for v in self.code_block:
            if v in self.first_code_valuate:
                first_code.append(v)
            if v in self.second_code_valuate:
                 second_code.append(v)
        v1 = 1.0*len(first_code)/len(self.first_code_valuate)
        v2 = 1.0*len(second_code)/len(self.second_code_valuate)
        return v1,v2 

    def tell_permis(self):
        permis_setting_list = self.permis_set_list()
        permis_list = []
        for v in permis_setting_list:
            if v in self.permis:
                permis_list.append(v)
        v1 = len(permis_list)
        v2 = len(permis_setting_list)
        return 1.0*v1/v2 

    def tell_act(self):
        sum_list = []
        act_set_list = self.get_act_set_list()
        for v in act_set_list:
            if v in self.recv_action:
                sum_list.append(v)
            if v in self.serv_action:
                sum_list.append(v)
        v1 = len(sum_list)
        v2 = len(act_set_list)
        return 1.0*v1/v2 

    def tell_rule(self):
        sender_list = ['19_a_11','19_a_12']
        execv_list = ['19_a_8','19_a_7','4_a_2_2']
        content_list = ['9_a_5','9_a_4','9_a_6_1','9_a_6_2','9_a_12','9_a_13_1','17_a_4','19_a_3','19_a_4']
        score = 0 
        sender_couter = self.get_sum(sender_list,self.code_block)
        execv_couter = self.get_sum(execv_list,self.code_block)
        content_couter = self.get_sum(content_list,self.code_block)
        if sender_couter != 0 and execv_couter != 0 and content_couter != 0:
            score = 30 + 10*content_couter/9.0 
        else:
            score = 10*content_couter/9.0
        return score 

    def virus_tell(self):
        v1,v2 = self.tell_code_block()#40
        v3 = self.tell_permis()#10
        v4 = self.tell_act()#10
        v5 = self.tell_rule()#40
        return v1*30.0 + v2*10.0 + v3*10.0 + v4*10.0 + v5