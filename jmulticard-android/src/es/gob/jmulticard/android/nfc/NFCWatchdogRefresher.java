// Code from https://gist.github.com/Thorbear/f7c48e90d3e71bde13cb
// Credit: Thorbear

package es.gob.jmulticard.android.nfc;

import android.annotation.TargetApi;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** <p>The purpose of this class is to keep the android system from
 * sending keep-alive commands to NFC tags.</p>
 * <p>This is necessary on some of the most common devices because
 * their implementation of keep-alive isn't according to the NFC
 * specification. The result of this is that a keep-alive command
 * can abort an authentication process that utilizes a
 * challenge-response mechanism, which Mifare DESFire does.</p>
 * <p>A common usage pattern will be to do some NFC communication,
 * call {@link #holdConnection(IsoDep)}, communicate with a webservice,
 * call {@link #stopHoldingConnection()}, and do some more NFC
 * communication.</p> */
@TargetApi(Build.VERSION_CODES.GINGERBREAD_MR1)
final class NFCWatchdogRefresher {

    private static final String TAG = NFCWatchdogRefresher.class.getSimpleName();
    private static final int TECHNOLOGY_ISO_DEP = 3;

    @Nullable
    private static HandlerThread sHandlerThread;

    @Nullable
    private static Handler sHandler;

    @Nullable
    private static WatchdogRefresher sRefresher;

    private static volatile boolean sIsRunning = false;

    /** <p>Should be called as soon as possible after the last NFC communication.</p>
     * <p>If this method is called multiple times without any calls to
     * {@link #stopHoldingConnection()}, each subsequent call will automatically
     * cancel the previous one.</p> */
    static void holdConnection(IsoDep isoDep) {
        Log.v(TAG, "holdConnection()");
        if (sHandlerThread != null || sHandler != null || sRefresher != null) {
            Log.d(TAG, "holdConnection(): Existing background thread found, stopping!");
            stopHoldingConnection();
        }
        sHandlerThread = new HandlerThread("NFCWatchdogRefresherThread");
        try {
            sHandlerThread.start();
        }
        catch (IllegalThreadStateException e) {
            Log.d(TAG, "holdConnection(): Failed starting background thread!", e);
        }
        final Looper looper = sHandlerThread.getLooper();
        if (looper != null) {
            sHandler = new Handler(looper);
        }
        else {
            Log.d(TAG, "holdConnection(): No looper on background thread!");
            sHandlerThread.quit();
            sHandler = new Handler();
        }
        sIsRunning = true;
        sRefresher = new WatchdogRefresher(sHandler, isoDep);
        sHandler.post(sRefresher);
    }

    /** Should be called before NFC communication is made if
     * {@link #holdConnection(IsoDep)} has been called since
     * the last communication. */
    static void stopHoldingConnection() {
        Log.v(TAG, "stopHoldingConnection()");
        sIsRunning = false;
        if (sHandler != null) {
            if (sRefresher != null) {
                sHandler.removeCallbacks(sRefresher);
            }
            sHandler.removeCallbacksAndMessages(null);
            sHandler = null;
        }
        if (sRefresher != null) {
            sRefresher = null;
        }
        if (sHandlerThread != null) {
            sHandlerThread.quit();
            sHandlerThread = null;
        }
    }

    /** Runnable that uses reflection to keep the NFC watchdog from
     * reaching its timeout and sending a keep-alive communication.
     * This works by telling the TagService to connect, if the tag
     * is already connected, it will return the success status and reset
     * the timeout.
     * The default timeout is 125ms, this runnable will call connect
     * every {@link #INTERVAL} (100ms). This runnable will self-terminate
     * after {@link #RUNTIME_MAX} has been reached (30 seconds) to avoid
     * accidentally leaking the thread. */
    private static final class WatchdogRefresher implements Runnable {

        /** Delay between each refresh in millis. */
        private static final int INTERVAL = 100;

        /** Used to ensure that this runnable self-stops after 30 seconds
         * if not stopped externally. */
        private static final int RUNTIME_MAX = 30 * 1000;

        private final WeakReference<Handler> mHandler;
        private final WeakReference<IsoDep> mIsoDep;
        private int mCurrentRuntime;

        private WatchdogRefresher(@NonNull Handler handler, @NonNull IsoDep isoDep) {
            mHandler = new WeakReference<Handler>(handler);
            mIsoDep = new WeakReference<IsoDep>(isoDep);
            mCurrentRuntime = 0;
        }

        @Override
        public void run() {
            final Tag tag = getTag();
            if (tag != null) {
                try {
                    final Method getTagService = Tag.class.getMethod("getTagService");
                    final Object tagService = getTagService.invoke(tag);
                    final Method getServiceHandle = Tag.class.getMethod("getServiceHandle");
                    final Object serviceHandle = getServiceHandle.invoke(tag);
                    final Method connect = tagService.getClass().getMethod("connect", int.class, int.class);
                    final Object result = connect.invoke(tagService, serviceHandle, TECHNOLOGY_ISO_DEP);

                    final Handler handler = getHandler();
                    if (result != null && result.equals(0) && handler != null && sIsRunning && mCurrentRuntime < RUNTIME_MAX) {
                        handler.postDelayed(this, INTERVAL);
                        mCurrentRuntime += INTERVAL;
                        Log.v(TAG, "Told NFC Watchdog to wait");
                    }
                    else {
                        Log.d(TAG, "result: " + result);
                    }
                }
                catch (final Exception e) {
                    Log.d(TAG, "WatchdogRefresher.run()", e);
                }
            }
        }

        @Nullable
        private Handler getHandler() {
            return mHandler.get();
        }

        @Nullable
        private Tag getTag() {
            final IsoDep isoDep = mIsoDep.get();
            if (isoDep != null) {
                return isoDep.getTag();
            }
            return null;
        }
    }
}