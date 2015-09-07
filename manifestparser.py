'''
Created on Jun 1, 2014

@author: Xbalien
'''

from androguard.core.bytecodes.apk import APK

class ManifestParser(object):
    '''
        This class is parse AndroidManifest.xml
    
        :param apk: specify the apk object
        :type apk: androguard.core.bytecodes.apk.APK
        :Example ManifestParser(apk)
    
    '''
    def __init__(self, apk):
        self.xml = apk.xml['AndroidManifest.xml']
        self.package = apk.package
        self.parse_res = {}
        self.androidversion = {}
        self.__comp_info = {}
        self.__components = []
        self.__comp_info = {}
        self.__providers = {}
        self.__activitys = {}
        self.__receivers = {}
        self.__services = {}
        self.__exported = {"activity":[], "service":[], "provider":[], "receiver":[]}
        self.__permissions = apk.permissions


    def analyzer_manifest(self):
        "Parse AndroidManifest.xml all component"             
        self.analyzer_component('activity')
        self.analyzer_component('service')
        self.analyzer_component('provider')
        self.analyzer_component('receiver')
    
        self.__components = self.__activitys.keys()
        self.__components.extend(self.__services.keys())
        self.__components.extend(self.__providers.keys())
        self.__components.extend(self.__receivers.keys())

        self.__format_result()


    def __implicit_exported(self, ilist):
        "implicit_exported test"
        for item in ilist:
            alist = item.getElementsByTagName('action')
            if alist:
                return True
        return False

    def __ifilter(self, ilist):
        "Parse Intent-filter detail"
        ifilter_infos = {}
        for item in ilist:
            action_list = []
            category_list = []
            data_list = []      
            priority = item.getAttribute('android:priority')
            if not priority:
                priority = 0
            
            alist = item.getElementsByTagName('action')
            for a in alist:
                action_list.append(a.getAttribute('android:name'))
            
            clist = item.getElementsByTagName('category')
            for a in clist:
                category_list.append(a.getAttribute('android:name'))
    
            dlist = item.getElementsByTagName('data')
            if dlist:
                for a in dlist:
                    key_list = a.attributes.keys()
                    value_list = []
                    for key in key_list:
                        value_list.append(a.getAttribute(key))
                    for num in range(len(key_list)):
                        dic = []
                        dic.append(key_list[num])
                        dic.append(value_list[num])
                        data_list.append(dic)
            
            ifilter_infos['priority'] = priority
            ifilter_infos['action'] = action_list
            ifilter_infos['category'] = category_list
            ifilter_infos['data'] = data_list

        return ifilter_infos   
    
    def analyzer_component(self, component): 
        '''
            Parse component from AndroidManifest.xml
            
            :param component: specify the type of component to parse
            :type component: string
            :Example analyzer_component('activity')
            
        '''
        
        iflist = []
        c_list = self.xml.getElementsByTagName(component)
        for item in c_list:
            name = item.getAttribute('android:name')
            if name.startswith('.'):
                name = self.package + name
            exported = item.getAttribute('android:exported')
            if not exported:

                son = item.getElementsByTagName('intent-filter')
                #if has intent-filter action
                if self.__implicit_exported(son):

                    exported = 'true'
                else:
                    exported = 'false'
                    
            permission = item.getAttribute('android:permission')
            if not permission:
                application = item.parentNode.getAttribute('android:permission')
                if application:
                    permission = application
                else:
                    permission = 'none'

            iflist = item.getElementsByTagName('intent-filter')
            if iflist:
                intentfilter = self.__ifilter(iflist)
            else:
                intentfilter = []

            attributes = {}
            attributes['exported'] = exported
            attributes['permission'] = permission
            attributes['intent-filter'] = intentfilter
            
            if component == 'activity':
                exclude_recent = item.getAttribute('android:excludeFromRecents')
                if not exclude_recent:
                    exclude_recent = 'false'
                    attributes['excludeFromRecents'] = exclude_recent
                self.__activitys[name] = attributes
                
            elif component == 'service':
                self.__services[name] = attributes
                
            elif component == 'provider':

                attributes['authorities'] = item.getAttribute('android:authorities')
                if attributes['authorities']:
                    attributes['exported'] = 'true'
                attributes['grantUriPermissions'] = item.getAttribute('android:grantUriPermissions')
                attributes['readPermission'] = item.getAttribute('android:readPermission')
                attributes['writePermission'] = item.getAttribute('android:writePermission')
                self.__providers[name] = attributes
                
            elif component == 'receiver':
                self.__receivers[name] = attributes

    def attacksurface(self):

        for component in self.__activitys:
            if self.__activitys[component]['exported'] == 'true':
                self.__exported['activity'].append(component)

        for component in self.__services:
            if self.__services[component]['exported'] == 'true':
                self.__exported['service'].append(component)

        for component in self.__receivers:
            if self.__receivers[component]['exported'] == 'true':
                self.__exported['receiver'].append(component)

        for component in self.__providers:
            if self.__providers[component]['exported'] == 'true':
                self.__exported['provider'].append(component)

        
    def __format_result(self):
        "Format the all components parse result"
        self.__comp_info['activity'] = self.__activitys
        self.__comp_info['service'] = self.__services
        self.__comp_info['provider'] = self.__providers
        self.__comp_info['receiver'] = self.__receivers
        self.parse_res[self.package] = self.__comp_info


    def get_package(self):
        """
            Return the name of the package
            :rtype: string
        """
        return self.package

    def get_androidversion_code(self):
        """
            Return the android version code
            :rtype: string
        """
        return self.androidversion["Code"]

    def get_androidversion_name(self):
        """
            Return the android version name
            :rtype: string
        """
        return self.androidversion["Name"]

    def get_AndroidManifest(self):
        """
            Return the Android Manifest XML file
            :rtype: xml object
        """
        return self.xml
    
    def get_perm_info(self):
        '''
            Return this APK declaration permission
            :rtype a dictionnary
        '''
        return self.__permissions

    def get_activitys(self):
        '''
            Return this APK declaration activitys name
            :rtype a list
        '''
        return self.__activitys.keys()
    
    def get_activitys_info(self):
        '''
            Return this APK declaration activitys information
            :rtype a dictionnary
        '''
        return self.__activitys
    
    def get_services(self):
        '''
            Return this APK declaration services name
            :rtype a list
        '''
        return self.__services.keys()

    def get_services_info(self):
        '''
            Return this APK declaration services information
            :rtype a dictionnary
        '''
        return self.__services
    
    def get_providers(self):
        '''
            Return this APK declaration providers name
            :rtype a list
        '''
        return self.__providers.keys()

    def get_providers_info(self):
        '''
            Return this APK declaration providers information
            :rtype a dictionnary
        '''
        return self.__providers

    def get_receivers(self):
        '''
            Return this APK declaration receivers name
            :rtype a list
        '''
        return self.__providers.keys()
    
    def get_receivers_info(self):
        '''
            Return this APK declaration receivers information
            :rtype a dictionnary
        '''
        return self.__receivers
    

    def get_all_components(self):
        '''
            Return this APK declaration all components name
            :rtype a list
        '''
        return self.__components


    def get_all_info(self):

        '''
            Return this APK declaration all components information
            :rtype a dictionnary
        '''
        return self.parse_res
    

    def get_exported(self):
        '''
            Return this APK declaration all exported components
            :rtype a dictionnary
        '''
        return self.__exported

    def is_declaration_component(self, component):
        '''
            Return declaration state for given component
            :rtype a boolean
        '''
        if component in self.__components:
            return True
        else:
            return False

    def is_exported_component(self, component):
        '''
            Return exported state for given component
            :rtype a boolean
        '''
        for (component_type, names) in self.__exported.items():
            if component in names:
                return True
        return False



def analyzeAPK(filename, raw = False, decompiler = None) :
 
    a = APK(filename, raw)
    return a

if __name__ == '__main__':
    
    apk = analyzeAPK('/mnt/hgfs/ubuntu12.04_share/app_audit/sobug/12/500_sports_scores_client_for_Android_1.3.2.10282.apk')
    #apk = analyzeAPK('../sampleapk/qiaoqiao2.1.apk')
    manifest_parser = ManifestParser(apk)
    manifest_parser.analyzer_manifest();

    print manifest_parser.get_all()
    manifest_parser.attacksurface()
    print manifest_parser.get_exported()




    
    
