'''
Created on Jun 8, 2014

@author: lyx
'''
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.decompiler.decompiler import DecompilerDAD



if __name__ == '__main__':
    apk = APK('../sampleapk/MyTrojan.apk')
    d = dvm.DalvikVMFormat(apk.get_dex())
    dx = analysis.uVMAnalysis(d)
    d.set_decompiler( DecompilerDAD( d, dx ) )
    for current_class in d.get_classes():
        s = current_class#.source()
    print s
    print s.source()
    '''for current_method in d.get_methods():  # @IndentOk
        x = current_method.get_code()
    ins = x.get_bc().get_instructions()
    i = 0
    for s in ins:
        print s.show(i)
        i += 1
    #apk = analyzeAPK('./sampleapk/k9-4.409-release.apk')'''
