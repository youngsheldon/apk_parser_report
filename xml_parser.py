#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os 
import re 
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
from xml.dom.minidom import parseString

class XmlParser(object):
    """docstring for XmlParser"""
    def __init__(self, path):
        self.path = path
        self.dom = self.initRun()

    def initRun(self):
        with open(self.path,'r') as f:
            data = f.read()
        return parseString(data)

    def praserPermissionOrAction(self,toparser):
        ret_list = []
        nodes = self.dom.getElementsByTagName(toparser)
        for node in nodes:
            if toparser == 'action':
                ret_list.append(node.toxml()[22:][:-3])
            elif toparser == 'uses-permission':
                ret_list.append(node.toxml()[31:][:-3])
        ret_list = list(set(ret_list))
        return ret_list

    def pattern(self,expr,data):
        results = re.compile(expr).findall(data) 
        return results

    def RelateAction(self,data,expr):
        action_list = []
        ret = self.pattern(expr,data)
        if ret:
            for item in ret:
                index = item.find('android:name=')
                v = item[index:].split('\"')[1]
                action_list.append(v)
            return action_list
        else:
            return None

    def Entrance(self,data,expr):
        ret = self.pattern(expr,data)[0]
        if ret:
            index = ret.find('android:name=')
            if 'permission' in ret:
                return ret[index:].split('\"')[1],ret[index:].split('\"')[3]
            else:
                return ret[index:].split('\"')[1],None
        else:
            return None

    def parserReceiver(self):
        out_dict = {}
        action_list = []
        nodes = self.dom.getElementsByTagName('receiver')
        for node in nodes:
            data = node.toxml()
            expr = r'\<receiver.*android:name=.*\>'
            entrance,request_permis = self.Entrance(data,expr)
            expr = r'\<action android:name=.*\/\>'
            action_list.append(request_permis)
            action_list.append(self.RelateAction(data,expr))
            out_dict[entrance] = action_list
            action_list = []
        return out_dict


    def parserService(self):
        out_dict = {}
        action_list = []
        nodes = self.dom.getElementsByTagName('service')
        for node in nodes:
            data = node.toxml()
            expr = r'\<service.*android:name=.*\>'
            entrance,request_permis = self.Entrance(data,expr)
            expr = r'\<action android:name=.*\/\>'
            action_list.append(request_permis)
            action_list.append(self.RelateAction(data,expr))
            out_dict[entrance] = action_list
            action_list = []
        return out_dict

    def parserSdkVersion(self):
        nodes = self.dom.getElementsByTagName('uses-sdk')
        v = nodes[0].toxml()
        minSdkVersion = v.split('\"')[1]
        tarSdkVersion = v.split('\"')[3]
        return minSdkVersion,tarSdkVersion 