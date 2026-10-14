import java.util.*;
public class Scope {
  static final String[] LIB = {"androidx/","android/","kotlin/","kotlinx/","java/","javax/","dalvik/","j$/","com/google/","com/android/","com/squareup/","okhttp3/","okio/","retrofit2/","org/apache/","org/jetbrains/","org/intellij/","org/bouncycastle/","org/conscrypt/","org/json/","org/slf4j/","org/w3c/","org/xmlpull/","org/threeten/","org/greenrobot/","com/facebook/","com/fasterxml/","com/bumptech/","com/airbnb/","com/jakewharton/","com/github/","com/crashlytics/","com/appsflyer/","com/adjust/","com/onesignal/","com/amplitude/","com/mixpanel/","com/unity3d/","com/applovin/","com/ironsource/","com/vungle/","com/mbridge/","com/chartboost/","com/bytedance/","com/huawei/","com/amazonaws/","com/microsoft/","com/twitter/","com/stripe/","com/paypal/","io/reactivex/","io/grpc/","io/sentry/","io/branch/","io/netty/","io/flutter/","dagger/","coil/","timber/","retrofit/","com/sun/","sun/","com/livechatinc/","com/zendesk/","com/intercom/","io/intercom/","com/sendbird/","com/freshchat/","com/clevertap/","com/segment/","com/instabug/","com/pusher/","io/socket/","org/chromium/","com/mapbox/","com/yandex/","com/tencent/","com/alibaba/","com/baidu/","com/braintreepayments/","com/datadog/","com/newrelic/","io/realm/","com/arthenica/","com/pubnub/","org/webrtc/","com/topjohnwu/","com/nulabinc/","org/joda/","org/acra/","org/mozilla/javascript/","org/maplibre/","coil3/","com/hcaptcha/","org/lsposed/","com/canhub/","org/jsoup/","com/nononsenseapps/","com/journeyapps/","com/caverock/","com/davemorrissey/","me/zhanghai/","org/commonmark/","org/kodein/","io/noties/","com/mikepenz/","com/google/zxing/","net/lingala/","com/nostra13/","com/squareup/picasso/","org/brotli/","org/tukaani/","org/spongycastle/","org/ejbca/","org/jmrtd/","net/sf/scuba/","com/sumsub/","com/onfido/","com/fingerprintjs/","io/ably/","com/microblink/","com/jumio/","com/veriff/","com/incode/","com/idnow/","com/gemalto/","org/spongycastle/","org/eclipse/jgit/","com/jcraft/jsch/","net/schmizz/","com/hierynomus/","org/pgpainless/","org/openintents/openpgp/","net/i2p/crypto/eddsa/","com/solana/","org/sol4k/","org/tron/","org/stellar/","org/web3j/","org/bitcoinj/","wallet/core/","org/ton/","io/github/novacrypto/"};
  static final String[] OV = {"org/schabi/newpipe/extractor/","org/fossify/commons/","com/simplemobiletools/commons/"};
  static boolean isOverride(String type) {
    String p = type.startsWith("L") ? type.substring(1) : type;
    for (String o : OV) if (p.startsWith(o)) return true;
    return false;
  }
  static boolean isLib(String type, String appPkg) {
    String p = type.startsWith("L") ? type.substring(1) : type;
    for (String o : OV) if (p.startsWith(o)) return true;
    if (!appPkg.isEmpty()) {
      String[] s = appPkg.split("\\.");
      String pref = (s.length >= 2 ? s[0] + "/" + s[1] : s[0]) + "/";
      if (p.startsWith(pref)) return false;
    }
    for (String l : LIB) if (p.startsWith(l)) return true;
    return false;
  }
}
