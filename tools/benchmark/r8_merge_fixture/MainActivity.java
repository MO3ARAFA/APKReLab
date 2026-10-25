package fx;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import java.io.File;

public class MainActivity extends Activity {
    static volatile Object sink;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        Intent i = getIntent();
        // origin A: a token entry; the caller's token is written into it here, and its own reader only logs it (not a sink)
        Registry.token = TokenEntry.empty();
        Registry.token.token = i.getStringExtra("token");
        Registry.token2 = TokenEntry.empty();
        Registry.token2.token = i.getStringExtra("token2");
        // origin B: session metadata with a fixed id; its reader deletes a file named by its own field
        Registry.session = new Metadata("session-1", getFilesDir());
        Registry.session2 = new Metadata("session-2", getCacheDir());
        //POS-BEGIN
        if (i.hasExtra("s")) {
            // origin B from caller input: a REAL flow through the shared field
            Registry.session3 = new Metadata("session-3", getCacheDir());
            Registry.session3.sessionId = i.getStringExtra("s");
        }
        //POS-END
        Registry.flushAll();
        Registry.describeAll();
        sink = String.valueOf(Registry.token) + Registry.session;
    }
}

final class TokenEntry {
    String token;
    private final StringBuilder status;
    private int reads;
    private TokenEntry(String token, StringBuilder status) { this.token = token; this.status = status; }
    static TokenEntry empty() { return new TokenEntry("", new StringBuilder(16)); }
    String describe() { reads++; for (int j = 0; j < reads; j++) status.append(token).append('/'); return status.toString(); }
    @Override public String toString() { return "T" + reads + status.length(); }
}

final class Metadata {
    String sessionId;
    private final Store store;
    private int flushes;
    Metadata(String sessionId, File dir) { this.sessionId = sessionId; this.store = new Store(dir); }
    void flush() { flushes++; for (int j = 0; j < flushes; j++) store.delete(sessionId); }
    @Override public String toString() { return "M" + flushes + store.hashCode(); }
}

final class Store {
    private final File dir;
    Store(File dir) { this.dir = dir; }
    void delete(String name) { if (!new File(dir, name).delete()) MainActivity.sink = name; }
}

final class Registry {
    static TokenEntry token, token2;
    static Metadata session, session2, session3;
    static void flushAll() { session.flush(); session2.flush(); if (session3 != null) session3.flush(); }
    static void describeAll() { MainActivity.sink = token.describe() + token2.describe(); }
}
