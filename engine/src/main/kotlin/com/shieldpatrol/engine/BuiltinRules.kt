package com.shieldpatrol.engine

/** 内置行为规则库：覆盖木马/隐私窃取/提权/后门/勒索/广告劫持/挖矿等家族特征组合。 */
object BuiltinRules {

    private const val INTERNET = "android.permission.INTERNET"
    private const val READ_SMS = "android.permission.READ_SMS"
    private const val SEND_SMS = "android.permission.SEND_SMS"
    private const val RECEIVE_SMS = "android.permission.RECEIVE_SMS"
    private const val READ_CONTACTS = "android.permission.READ_CONTACTS"
    private const val WRITE_CONTACTS = "android.permission.WRITE_CONTACTS"
    private const val READ_CALL_LOG = "android.permission.READ_CALL_LOG"
    private const val CAMERA = "android.permission.CAMERA"
    private const val RECORD_AUDIO = "android.permission.RECORD_AUDIO"
    private const val READ_EXTERNAL = "android.permission.READ_EXTERNAL_STORAGE"
    private const val WRITE_EXTERNAL = "android.permission.WRITE_EXTERNAL_STORAGE"
    private const val SAW = "android.permission.SYSTEM_ALERT_WINDOW"
    private const val QAP = "android.permission.QUERY_ALL_PACKAGES"
    private const val BOOT = "android.permission.RECEIVE_BOOT_COMPLETED"
    private const val WAKE = "android.permission.WAKE_LOCK"

    fun all(): List<Rule> = listOf(
        // —— 隐私窃取 ——
        Rule("SMS_READ", ThreatCategory.TROJAN, 30, listOf(PermAny(setOf(READ_SMS))), "读取短信内容"),
        Rule("SMS_SEND", ThreatCategory.TROJAN, 25, listOf(PermAny(setOf(SEND_SMS))), "发送短信"),
        Rule("SMS_INTERCEPT", ThreatCategory.TROJAN, 15, listOf(PermAny(setOf(RECEIVE_SMS))), "拦截短信"),
        Rule("CONTACTS_WRITE", ThreatCategory.PRIVACY_STEALER, 15, listOf(PermAny(setOf(WRITE_CONTACTS))), "改写通讯录"),
        Rule("MIC_CAMERA_BOTH", ThreatCategory.PRIVACY_STEALER, 20, listOf(PermAll(setOf(CAMERA, RECORD_AUDIO))), "同时调用摄像头与麦克风"),
        Rule("LOCATION_BG_NET", ThreatCategory.PRIVACY_STEALER, 30, listOf(PermAll(setOf("android.permission.ACCESS_BACKGROUND_LOCATION", INTERNET))), "后台定位+联网（位置跟踪）"),
        Rule("PRIVACY_EXFIL", ThreatCategory.PRIVACY_STEALER, 40, listOf(PermAny(setOf(READ_SMS, READ_CONTACTS, READ_CALL_LOG)), PermAny(setOf(INTERNET)), DexAny(setOf("getWallpaper", "sms://", "content://sms", "telephony.Sms"))), "敏感数据+联网+短信/通话内容访问"),
        Rule("ACCESSIBILITY_ABUSE", ThreatCategory.PRIVACY_STEALER, 75, listOf(CompAny(ComponentType.SERVICE, "accessibility"), PermAny(setOf(READ_SMS, INTERNET, "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"))), "无障碍服务+敏感能力（可读取屏幕验证码并静默操作）"),
        Rule("DEVICE_ADMIN_REQUEST", ThreatCategory.TROJAN, 30, listOf(PermAny(setOf("android.permission.BIND_DEVICE_ADMIN"))), "申请设备管理器（强卸载门槛）"),
        // —— 短信扣费木马 ——
        Rule("SPAM_SMS_COMBINATION", ThreatCategory.TROJAN, 70, listOf(PermAll(setOf(READ_SMS, RECEIVE_SMS, SEND_SMS))), "短信读+收+发三权限组合（验证码窃取/扣费）"),
        Rule("SPAM_SMS_MAXSDK", ThreatCategory.TROJAN, 70, listOf(PermAny(setOf(SEND_SMS)), MaxTargetSdk(22)), "低targetSdk自申请短信发送（规避权限弹窗）"),
        // —— 提权/危险命令 ——
        Rule("ROOT_PROBE", ThreatCategory.BACKDOOR, 20, listOf(DexAny(setOf("su -c", "/system/xbin/su"))), "探测 root 执行环境"),
        Rule("ROOT_EXPLOIT", ThreatCategory.TROJAN, 60, listOf(DexAny(setOf("id=0", "permissive=1", "setenforce")), FlagUnknown()), "疑似 root 提权特征"),
        Rule("DEBUG_BUILD", ThreatCategory.GENERIC, 10, listOf(FlagDebug()), "调试版安装包（常见于二次打包）"),
        Rule("UNKNOWN_SOURCE", ThreatCategory.GENERIC, 15, listOf(FlagUnknown()), "非应用商店侧载安装"),
        // —— 后门/远控 ——
        Rule("DYN_CODELOADER", ThreatCategory.GENERIC, 25, listOf(FlagDynamic()), "运行时动态加载代码"),
        Rule("DYN_NET", ThreatCategory.BACKDOOR, 35, listOf(FlagDynamic(), PermAny(setOf(INTERNET))), "动态加载代码+联网（可热更恶意逻辑）"),
        Rule("REVSHELL", ThreatCategory.BACKDOOR, 60, listOf(DexAny(setOf("/system/bin/sh -c")), PermAny(setOf(INTERNET))), "执行 shell 命令+联网"),
        Rule("ROOT_SHELL", ThreatCategory.BACKDOOR, 50, listOf(DexAny(setOf("/system/bin/sh -c", "/system/xbin/su")), FlagDynamic()), "shell+动态加载组合"),
        Rule("C2_OVERLAY", ThreatCategory.BACKDOOR, 70, listOf(PermAll(setOf(SAW, QAP, INTERNET)), DexAny(setOf("/system/bin/sh -c"))), "命令控制特征：悬浮窗+全包查询+shell"),
        // —— 勒索 ——
        Rule("RANSOM_FILEOPS", ThreatCategory.RANSOMWARE, 60, listOf(DexAny(setOf("listFiles", "renameTo")), PermAll(setOf(READ_EXTERNAL, WRITE_EXTERNAL))), "大范围文件枚举+重命名（加密勒索前置行为）"),
        Rule("RANSOM_NOTE", ThreatCategory.RANSOMWARE, 75, listOf(DexAny(setOf("HOWTORECOVERFILES.txt", "recover", "decrypt", "aes_encrypt")), PermAny(setOf(WRITE_EXTERNAL))), "勒索提示/加密特征"),
        Rule("RANSOM_DISABLE_SETTINGS", ThreatCategory.RANSOMWARE, 50, listOf(DexAny(setOf("Settings.ACTION_SECURITY", "Settings.ACTION_DEVICE_ADMIN_SETTINGS", "device_admin"))), "诱导关闭系统安全设置"),
        // —— 广告劫持 ——
        Rule("AD_OVERLAY", ThreatCategory.ADWARE, 20, listOf(PermAll(setOf(SAW, INTERNET)), MaxTargetSdk(25)), "低targetSdk申请悬浮窗（绕过授权弹窗）"),
        Rule("QUERY_ALL_PACKAGES", ThreatCategory.ADWARE, 5, listOf(PermAny(setOf(QAP))), "枚举全部已安装应用"),
        Rule("AD_OVERLAY_HIJACK", ThreatCategory.ADWARE, 70, listOf(PermAll(setOf(SAW, QAP)), PermAny(setOf(INTERNET)), DexAny(setOf("TYPE_APPLICATION_OVERLAY"))), "全屏覆盖+应用枚举（可劫持登录/支付界面）"),
        // —— 挖矿 ——
        Rule("MINER_POOL", ThreatCategory.MINER, 80, listOf(DexAny(setOf("stratum", "xmrig", "minerd", "coinhive", "monero"))), "矿池地址或矿工程序特征"),
        Rule("MINER_WAKE", ThreatCategory.MINER, 30, listOf(DexAny(setOf("wakelock")), PermAny(setOf(BOOT, WAKE))), "保活+开机驻留（配合高耗电）"),
    )
}
