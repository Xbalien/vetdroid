'''
Created on Jun 3, 2014

@author: Xbalien
'''


import sys
import staticuitls
import os
from optparse import OptionParser
from manifestparser import ManifestParser
from sourceaudit import SourceAudit
from showaudit import ShowSourceAudit
from showaudit import ShowMenifestAudit
from showaudit import ShowReachAPI

DIR = r"sampleapk/"

def manifest_config_attacksurface(apk):

    allow_backup = apk.get_element('application','android:allowBackup')
    debuggable = apk.get_element('application','android:debuggable')
    manifestparser = ManifestParser(apk)
    manifestparser.analyzer_manifest()
    manifestparser.attacksurface()
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

def reach_api_analysis(d, dx):

    sourceaudit = SourceAudit(d, dx)
    res = sourceaudit.reach_api_analysis()
    return res


if __name__ == '__main__':

    usage = "usage: %prog -f apk_path -m mode [1:start api_misuse audit 2:start reach_api analysis] "

    parser = OptionParser(usage)
    parser.add_option("-f", "--apk_path", dest="apk_path", help="apk name to static audit")
    parser.add_option("-m", "--mode", dest="mode", help="which mode to running")

    (options, args) = parser.parse_args()

    print "start analysis ..."

    if options.mode == "1":
        print "start api_misuse audit ..."
        apk_path = options.apk_path
        
        apk, d, dx = staticuitls.AnalyzeAPK(apk_path, decompiler="dad")
        attacksurface, allow_backup, debuggable = manifest_config_attacksurface(apk)
        webview, register_receiver, https_res, intent_scheme_res, log_res = source_attacksurface(d, dx)

        fd = open(DIR + 'audit_res_' + apk.package, 'wb')

        ShowSourceAudit(fd, webview, register_receiver, https_res, intent_scheme_res, log_res).show()
        ShowMenifestAudit(fd, attacksurface, allow_backup, debuggable).show()

        fd.close()


    if options.mode == "2":
        print "start reach_api analysis ..."
        apk_path = options.apk_path
        apk, d, dx = staticuitls.AnalyzeAPK(apk_path, decompiler="dad")

        fd = open(DIR + 'reach_res_' + apk.package, 'wb')
        ShowReachAPI(fd, reach_api_analysis(d, dx)).show()
        fd.close()

    print "ending ..."

