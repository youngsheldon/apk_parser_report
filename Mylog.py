#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: anchen
# @Date:   2016-09-08 11:17:18
# @Last Modified by:   anchen
# @Last Modified time: 2016-09-09 08:42:10
import logging

class Mylog():
    """docstring for Mylog"""
    def __init__(self,file):
        self.file = file 
        self.infoLogger = logging.getLogger("infoLog")
        self.infoHandler = logging.FileHandler(self.file, 'a')
        self.initLog()

    def setHandler(self):
        format='[%(asctime)s] [%(levelname)s] %(filename)s:%(lineno)d %(message)s'
        formatter = logging.Formatter(format)
        self.infoHandler.setLevel(logging.INFO)
        self.infoHandler.setFormatter(formatter)

    def initLog(self):
        self.infoLogger.setLevel(logging.INFO)
        self.setHandler()
        self.infoLogger.addHandler(self.infoHandler)

    def getObject(self):
        return self.infoLogger

