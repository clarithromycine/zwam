# coding=UTF-8
import os
import logging

logger = logging.getLogger(__name__)

class ApiCmd(object):
    def __init__(self, cmd , desc, order = 0):
        self.cmd  = cmd
        self.desc = desc
        self.order = order
    def __call__(self, fn):
        fn.cmd = self.cmd
        fn.desc = self.desc
        fn.order = self.order
        return fn   

class Utils:

    _OUTPUT = []
    
    @staticmethod
    def assureDir(path):            
        try:    
            if not os.path.exists(path):
                os.makedirs(path)
        except:
            #有时候并发创建目录会出异常，直接忽略就好
            pass

    @staticmethod
    def getOption(options,name,default=None):
        if name in options:
            return options[name]
        else:
            return default

    
    @staticmethod
    def cmdLineParser(args):
        options = {}
        params = []
        if len(args)==1:
            return params,options 
        i = 1
        while i<len(args):
            if args[i].startswith("--"):                
                if i+1>=len(args) or args[i+1].startswith("--") :
                    options[args[i][2:]] = True
                    i+=1
                else:
                    options[args[i][2:]] = args[i+1]
                    i+=2
            else:
                params.append(args[i])
                i+=1
        return params,options




    

                

          

            
    
    
    


        
        




