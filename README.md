# vetdroid
> 该demo项目主要基于androguard，可以实现一些简单的api误用静态审计，menifest配置误用以及自定义api调用分析.（没有数据流分析，用于简单审计和静态特征定位）

> api误用静态审计可以用于 WebView addJavascriptInterface,setHostnameVerifier,Intent parseUri,registerReceiver以及一些暴露组件可调备份.

> api调用分析.在api_reach_list可以添加需要检测的api调用，写法如smali语法Landroid/content/Intent;->getStringExtra


# 运行
    python staticaudit.py -f apk_path -m mode [1:start api_misuse audit 2:start reach_api analysis]

# 结果

> /sampleapk/audit_res_com.wisorg.fzdx 简单静态审计结果

> /sampleapk/reach_res_com.wisorg.fzdx 简单api调用结果

# 备注

> 误报较高，仅仅用于快速定位特征 
    
