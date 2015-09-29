'''
Created on Jun 3, 2014

@author: Xbalien
'''


import sys
import staticuitls
import apkparser
import os
from optparse import OptionParser
from apkparser import ManifestParser
from apkparser import DexStringParser
from sourceaudit import SourceAudit
from showaudit import ShowSourceAudit
from showaudit import ShowMenifestAudit
from showaudit import ShowReachAPI

DIR = r'sampleapk/'
URI_FILE = r'.content_uri'


def start_apk_parse(apk_path):
    dex_string = DexStringParser(apk_path, DIR + URI_FILE)
    dex_string.parse_all_providers_uris()

    manifest_parser = ManifestParser(apk_path)
    manifest_parser.analyzer_manifest();
    manifest_parser.attacksurface()

    return dex_string, manifest_parser


def manifest_config_attacksurface(manifest_parser):

    print manifest_parser.get_all_components()
    print manifest_parser.get_exported_detail()
    print manifest_parser.get_exported()
    print manifest_parser.get_exported_activity_count()
    print manifest_parser.get_exported_service_count()
    print manifest_parser.get_exported_provider_count()
    print manifest_parser.get_exported_receiver_count()
    print manifest_parser.get_allow_backup()
    print manifest_parser.get_debuggable()
    print manifest_parser.get_name()
    print manifest_parser.get_size()
    print manifest_parser.get_md5()
    print manifest_parser.get_sha1()
    print manifest_parser.get_sha256()
    print manifest_parser.get_androidversion_name()
    print manifest_parser.get_androidversion_code()
    print manifest_parser.get_package_name()
    print manifest_parser.get_permissions()
    print manifest_parser.get_min_sdk()
    print manifest_parser.get_target_sdk()
    print manifest_parser.get_share_user_id()
    print manifest_parser.get_main_activity()
    print manifest_parser.get_details_permissions()
    return manifest_parser.get_exported(), manifest_parser.get_allow_backup(), manifest_parser.get_debuggable()

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

    usage = 'usage: %prog -f apk_path -m mode [1:start api_misuse audit 2:start reach_api analysis] '

    parser = OptionParser(usage)
    parser.add_option('-f', '--apk_path', dest='apk_path', help='apk name to static audit')
    parser.add_option('-m', '--mode', dest='mode', help='which mode to running')

    (options, args) = parser.parse_args()

    if options.apk_path == None:
        parser.error('incorrect arguments')
        
    print 'start analysis ...'

    if options.mode == '1':
        print 'start api_misuse and manifest audit ...'
        apk_path = options.apk_path
        
        apk, d, dx = staticuitls.AnalyzeAPK(apk_path, decompiler='dad')
        dex_string, manifest_parser = start_apk_parse(apk_path)
        attacksurface, allow_backup, debuggable = manifest_config_attacksurface(manifest_parser)
        webview, register_receiver, https_res, intent_scheme_res, log_res = source_attacksurface(d, dx)

        fd = open(DIR + 'audit_res_' + apk.package, 'wb')

        ShowSourceAudit(fd, webview, register_receiver, https_res, intent_scheme_res, log_res).show()
        ShowMenifestAudit(fd, attacksurface, allow_backup, debuggable).show()

        fd.close()


    if options.mode == '2':
        print 'start reach_api analysis ...'
        apk_path = options.apk_path
        apk, d, dx = staticuitls.AnalyzeAPK(apk_path, decompiler='dad')

        fd = open(DIR + 'reach_res_' + apk.package, 'wb')
        ShowReachAPI(fd, reach_api_analysis(d, dx)).show()
        fd.close()

    if options.mode == '3':
        print 'start manifest audit and find content uris ...'
        apk_path = options.apk_path
        dex_string, manifest_parser = start_apk_parse(apk_path)
        manifest_config_attacksurface(manifest_parser)
        apkparser.find_content_uris(dex_string, manifest_parser.get_package_name())

    print 'ending ...'

