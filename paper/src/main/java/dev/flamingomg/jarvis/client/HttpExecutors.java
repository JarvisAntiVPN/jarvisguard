package dev.flamingomg.jarvis.client;

import java.net.http.HttpClient;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class HttpExecutors {

    private HttpExecutors() {}

    public static ExecutorService daemonHttpExecutor(String namePrefix) {
        ThreadFactory factory = new ThreadFactory() {
            private final AtomicInteger n = new AtomicInteger(1);
            @Override public Thread newThread(Runnable r) {
                Thread t = new Thread(r, namePrefix + "-" + n.getAndIncrement());
                t.setDaemon(true);
                return t;
            }
        };

        ThreadPoolExecutor pool = new ThreadPoolExecutor(0, Integer.MAX_VALUE,
                60L, TimeUnit.SECONDS, new SynchronousQueue<>(), factory);
        return pool;
    }

    public static void closeQuietly(HttpClient http) {
        if (http == null) return;
        try {

            HttpClient.class.getMethod("close").invoke(http);
        } catch (NoSuchMethodException notSupported) {

        } catch (Exception ignored) {

        }
    }

    public static void shutdownQuietly(ExecutorService exec) {
        if (exec == null) return;
        try {
            exec.shutdown();
            if (!exec.awaitTermination(2, TimeUnit.SECONDS)) exec.shutdownNow();
        } catch (InterruptedException e) {
            exec.shutdownNow();
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
        }
    }
}
