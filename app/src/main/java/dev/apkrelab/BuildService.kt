package dev.apkrelab

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Foreground service that keeps the process alive (and shows a progress notification) while a Build runs.
 * The build itself still runs in a Thread started by MainActivity; this service only holds the process.
 * Build state (log text, running flag) lives here so it survives Activity recreation.
 */
class BuildService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureChannel(this)
        val n = buildNotif(this, "Starting...", 0)
        if (Build.VERSION.SDK_INT >= 29) startForeground(ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        else startForeground(ID, n)
        fgStarted = true
        return START_NOT_STICKY
    }

    companion object {
        const val ID = 4201
        const val DONE_ID = 4202
        const val CHANNEL = "build"

        val text = StringBuilder()
        @Volatile var running = false
        // 0.12.4: stopService() before onStartCommand()->startForeground() ran crashes the app
        // (ForegroundServiceDidNotStartInTimeException) when a build fails within milliseconds.
        @Volatile private var startRequested = false
        @Volatile private var fgStarted = false

        private fun ensureChannel(ctx: Context) {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL) == null) {
                nm.createNotificationChannel(NotificationChannel(CHANNEL, "APK build", NotificationManager.IMPORTANCE_LOW))
            }
        }

        private fun buildNotif(ctx: Context, msg: String, step: Int, ongoing: Boolean = true): Notification {
            val open = PendingIntent.getActivity(
                ctx, 0,
                Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            val b = Notification.Builder(ctx, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle(if (ongoing) "APK ReLab: building..." else "APK ReLab")
                .setContentText(msg)
                .setContentIntent(open)
                .setOngoing(ongoing)
                .setOnlyAlertOnce(true)
            if (ongoing) b.setProgress(4, step, step == 0)
            return b.build()
        }

        fun start(ctx: Context) {
            running = true
            fgStarted = false
            ctx.startForegroundService(Intent(ctx, BuildService::class.java))
            startRequested = true
        }

        /** Called for every log line; updates the notification text and the [n/4] progress bar. */
        fun update(ctx: Context, msg: String) {
            val line = msg.trim().lineSequence().firstOrNull() ?: return
            if (line.isEmpty()) return
            val step = rx("^\\[(\\d)/4]").find(line)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            try {
                ctx.getSystemService(NotificationManager::class.java).notify(ID, buildNotif(ctx, line.take(100), step))
            } catch (_: Throwable) { }
        }

        fun finish(ctx: Context, msg: String) {
            running = false
            if (startRequested) {
                // called from the build thread (never the UI thread): wait until the service reached startForeground()
                val t0 = System.currentTimeMillis()
                while (!fgStarted && System.currentTimeMillis() - t0 < 3000) {
                    try { Thread.sleep(50) } catch (_: InterruptedException) { break }
                }
                startRequested = false
            }
            try {
                ctx.stopService(Intent(ctx, BuildService::class.java))
                ensureChannel(ctx)
                ctx.getSystemService(NotificationManager::class.java)
                    .notify(DONE_ID, buildNotif(ctx, msg, 0, ongoing = false).also { })
            } catch (_: Throwable) { }
        }
    }
}
