'''
Created on Jun 3, 2014

@author: Xbalien
'''


import re
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis

REACH_API_LIST = r"api_reach_list"

class SourceAudit(object):
    '''
        This class is analysis source to audit 
    
        :param d: specify the DalvikVMFormat object
        :param dx: specify the VMAnalysis object
        :type d: androguard.core.bytecodes.dvm.DalvikVMFormat
        :type dx: androguard.core.analysis.VMAnalysis
        :Example SourceAudit(d, dx)
    
    '''
    def __init__(self, d, dx):

        self.d = d
        self.dx = dx
        self.webview = {}
        self.register_receiver = {}
        self.https = {}
        self.log = {}
        self.reach_api_res = {}
        self.reach_api_list = []
    
    def webview_audit(self):
        self.webview = self.__mathods_search(".", "addJavascriptInterface", ".")

    def register_receiver_audit(self):  
        self.register_receiver = self.__mathods_search(".", "registerReceiver", ".")

    def https_audit(self):
        self.https = self.__mathods_search("Lorg/apache/http/conn/ssl/SSLSocketFactory;", "setHostnameVerifier", ".")

    def intent_scheme_audit(self):
        self.intent_scheme = self.__mathods_search("Landroid/content/Intent;", "parseUri", ".")

    def log_audit(self):
        #self.log = self.__mathods_search("Landroid/util/Log;", "i", ".")
        pass

    def reach_api_analysis(self, is_java = True):
        res = ""
        with open(REACH_API_LIST,'rb') as fd:
            reach_api_list = fd.readlines()

        for reach_api in reach_api_list:
            api_detail = reach_api.split("->")
            package_name = api_detail[0]
            method_name = api_detail[1]
            res += ("################################### %s ###################################" % (reach_api) + '\n')

            reach = self.__mathods_search(package_name, method_name, ".", is_java)
            if reach:
                for key in reach:
                    res += (key) + reach[key] + '\n'
            else:
                res += "None\n"

        return res


    
    def __mathods_search(self, package_name, method_name, descriptor, is_java = True) :
        '''
            This method is search method's ref and get the method's java source

            :param package_name: specify the taint class name
            :param method_name: specify the taint mathod name
            :param is_java: to java
            :type package_name: string
            :type method_name: string
            :type is_java: bool
        '''
        nodes = []
        names = {}
        analysis_res = {}
        tainted_packages = self.dx.get_tainted_packages()
        
        paths = tainted_packages.search_methods(package_name, method_name, descriptor)
        if not paths:
            return
    
        #analysis.show_Paths(self.d, paths)
        #path's struct {'src': 'Lclass; method(parm_type;parm_type;)ret_type;', 'dst': 'Lclass; method(parm_type;parm_type;)ret_type;', 'idx': 170}
        #nodes containt many path's struct
        
        for path in paths:
            nodes.append(analysis.get_Path(self.d, path))

        for node in nodes:
            tmp = node["src"].split(" ")
            #names struct : {'class':['method_name']['method_name']}
            if names.has_key(tmp[0]):
                names[tmp[0]].append(tmp[1])
            else:
                names[tmp[0]] = []
                names[tmp[0]].append(tmp[1])
    
        #print names :src class and method

        for current_class in self.d.get_classes():
            class_name = current_class.get_name()
            #this class is the src class for tainted method
            if names.has_key(class_name):
                for method in current_class.get_methods():
                    name = method.get_name()
                    #src method to call tainted method
                    if name in names[class_name]:
                        if is_java == True:
                            java = method.get_source()
                            java_code = java.split("\n")
                            for code in java_code:
                                if code.find(method_name) != -1:
                                    analysis_res["%s->%s.java:%s" % (class_name, name, code.lstrip())]=java
                        else:
                            analysis_res["%s->%s.java: --> %s->%s" % (class_name, name, package_name, method_name)] = "reach"

        return analysis_res

    def get_webview_res(self):
        return self.webview

    def get_register_receiver(self):
        return self.register_receiver

    def get_https(self):
        return self.https

    def get_intent_scheme(self):
        return self.intent_scheme

    def get_logs(self):
        return self.log


        
        
        