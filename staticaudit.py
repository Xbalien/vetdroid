import sys
import staticuitls
from manifestparser import ManifestParser
from sourceaudit import SourceAudit



def manifest_config_attacksurface(apk):

    allow_backup = apk.get_element('application','android:allowBackup')
    debuggable = apk.get_element('application','android:debuggable')
    manifestparser = ManifestParser(apk)
    manifestparser.analyzer_manifest()
    manifestparser.attacksurface()
    manifestparser.xml
    return manifestparser.get_exported(), allow_backup, debuggable

def source_attacksurface(d, dx):

    sourceaudit = SourceAudit(d, dx)
    sourceaudit.webview_audit()
    sourceaudit.register_receiver_audit()
    sourceaudit.https_audit()
    sourceaudit.intent_scheme_audit()
    sourceaudit.log_audit()

    return sourceaudit.get_webview_res(), sourceaudit.get_register_receiver(), \
        sourceaudit.get_https(), sourceaudit.get_intent_scheme(), sourceaudit.get_logs()



if __name__ == '__main__':

    res = ""
    apk, d, dx = staticuitls.AnalyzeAPK(sys.argv[1],decompiler="dad")
    attacksurface, allow_backup, debuggable = manifest_config_attacksurface(apk)
    webview, register_receiver, https_res, intent_scheme_res, log_res = source_attacksurface(d, dx)
    print "################################ webview ######################################"
    res += ("################################ webview ######################################" + '\n')
    if webview:
        for key in webview:
            print key
            print webview[key]
            res += (key + '\n') + webview[key]
    else:
        print "None"

    print "################################ https ######################################" 
    res += ("################################ https ######################################" + '\n')
    if https_res:
        for key in https_res:
            print key
            print https_res[key]
            res += (key + '\n') + https_res[key]
    else:
        print "None"



    print "################################ intent_scheme ######################################" 
    res += ("################################ intent_scheme ######################################" + '\n')
    if intent_scheme_res:
        for key in intent_scheme_res:
            print key
            print intent_scheme_res[key]
            res += (key + '\n') + intent_scheme_res[key]
    else:
        print "None"


    print "################################ logcat ######################################" 
    res += ("################################ logcat ######################################" + '\n')
    if log_res:
        for key in log_res:
            print key
            print log_res[key]
            res += (key + '\n') + log_res[key]
    else:
        print "None"



    print "################################ manifest_config ######################################" 
    if allow_backup:
        print "allow_backup : %s" % allow_backup
    else :
        print "allow_backup : true" 

    if debuggable:
        print "debuggable : %s" % debuggable
    else :
        print "debuggable : false"


    for component_type in attacksurface:
        print "################################### %s ###################################" % (component_type.upper())
        res += (component_type.upper() + '\n')
        for component in attacksurface[component_type]:
            print component
            res += (component + '\n')



    print "################################ register_receiver ######################################" 
    res += ("################################ register_receiver ######################################" + '\n')
    if register_receiver:
        for key in register_receiver:
            print key
            print register_receiver[key]
            res += (key + '\n') + register_receiver[key]
    else:
        print "None"
    #fd = open(sys.argv[2], 'w')
    #fd.write(res)
    #fd.close()


