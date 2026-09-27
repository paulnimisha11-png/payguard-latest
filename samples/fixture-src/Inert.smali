.class public Ltests/androguard/Inert;
.super Ljava/lang/Object;
.source "Inert.java"
# DETECTION TEST FIXTURE ONLY. Never called. Contains only string constants
# and unreachable references so the scanner can be tested.

.method public static never()V
    .registers 8
    const-string v0, "https://api.telegram.org/bot7012345678:AAHfakeTOKENfakeTOKENfakeTOKENfake12/sendMessage"
    const-string v0, "content://sms/inbox"
    const-string v0, "tel:*21*"
    const-string v0, "com.sbi.lotusintouch"
    const-string v0, "com.snapwork.hdfc"
    const-string v0, "com.csam.icici.bank.imobile"
    const-string v0, "com.axis.mobile"
    const-string v0, "http://45.137.21.9:8080/panel/upload.php"
    const-string v0, "https://track-parcel-india.xyz/api"
    return-void
.end method

.method public static refs(Landroid/telephony/SmsManager;Landroid/accessibilityservice/AccessibilityService;[B)V
    .registers 9
    const/4 v0, 0x0
    invoke-static {p2}, Landroid/telephony/SmsMessage;->createFromPdu([B)Landroid/telephony/SmsMessage;
    move-result-object v1
    invoke-virtual {v1}, Landroid/telephony/SmsMessage;->getMessageBody()Ljava/lang/String;
    invoke-virtual {p1, v0}, Landroid/accessibilityservice/AccessibilityService;->performGlobalAction(I)Z
    return-void
.end method
