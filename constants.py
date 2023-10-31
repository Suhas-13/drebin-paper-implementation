import os

ANDROID_SUSPICIOUS_NAME_LIST = [
    "getExternalStorageDirectory", "getSimCountryIso", "execHttpRequest", 
    "sendTextMessage", "getSubscriberId", "getDeviceId", "getPackageInfo", 
    "getSystemService", "getWifiState", "setWifiEnabled", "setWifiDisabled", 
    "Cipher", "Obfuscation", "getCellLocation"
]

OTHER_SUSPICIOUS_NAME_LIST = [
    "Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;)", "Ljava/net/HttpURLconnection", 
    "Lorg/apache/http/client/methods/HttpPost", "Landroid/telephony/SmsMessage;->getMessageBody", 
    "Ljava/io/IOException;->printStackTrace", "Ljava/lang/Runtime;->exec"
]

NOT_API_NAME_LIST = ["system/bin/su", "android/os/Exec"]

CIPHER_KEYWORDS = [
    "AES", "DES", "DESede", "RSA", "ECB", "CBC", "PKCS5Padding", 
    "PKCS7Padding", "NoPadding", "BKS", "PKCS12", "BC"
]

ALL_SUSPICIOUS_NAME_LIST = ANDROID_SUSPICIOUS_NAME_LIST + OTHER_SUSPICIOUS_NAME_LIST + NOT_API_NAME_LIST

DATA_DIR = "data"
APK_DIR = "apks"
BENIGN_DIR = os.path.join(APK_DIR, "benign")
MALICIOUS_DIR = os.path.join(APK_DIR, "malicious")

PERMISSIONS_FILE = os.path.join(DATA_DIR, "PScoutPermApiDict.json")