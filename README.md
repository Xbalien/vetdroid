# vetdroid
> ��demo��Ŀ��Ҫ����androguard������ʵ��һЩ�򵥵�api���þ�̬��ƣ�menifest���������Լ��Զ���api���÷���.��û�����������������ڼ���ƺ;�̬������λ��

> api���þ�̬��ƿ������� WebView addJavascriptInterface,setHostnameVerifier,Intent parseUri,registerReceiver�Լ�һЩ��¶����ɵ�����.

> api���÷���.��api_reach_list���������Ҫ����api���ã�д����smali�﷨Landroid/content/Intent;->getStringExtra


# run
    python staticaudit.py -f apk_path -m mode [1:start api_misuse audit 2:start reach_api analysis]

# result

> /sampleapk/audit_res_com.wisorg.fzdx �򵥾�̬��ƽ��

> /sampleapk/reach_res_com.wisorg.fzdx ��api���ý��

# ps

> �󱨽ϸߣ��������ڿ��ٶ�λ���� 
    
