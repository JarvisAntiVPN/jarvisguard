package dev.flamingomg.jarvis.client;

import java.net.http.HttpClient;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class HttpExecutors {

    private HttpExecutors() {}

    private static final int HTTP_MAX_THREADS =
            Math.max(8, Math.min(32, Runtime.getRuntime().availableProcessors() * 2));
    private static final int HTTP_QUEUE_CAPACITY = 256;

    public static ExecutorService daemonHttpExecutor(String namePrefix) {
        ThreadFactory factory = new ThreadFactory() {
            private final AtomicInteger n = new AtomicInteger(1);
            @Override public Thread newThread(Runnable r) {
                Thread t = new Thread(r, namePrefix + "-" + n.getAndIncrement());
                t.setDaemon(true);
                return t;
            }
        };
        ThreadPoolExecutor pool = new ThreadPoolExecutor(HTTP_MAX_THREADS, HTTP_MAX_THREADS,
                60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(HTTP_QUEUE_CAPACITY), factory,
                new ThreadPoolExecutor.CallerRunsPolicy());
        pool.allowCoreThreadTimeOut(true);
        return pool;
    }

    static final long CIERRE_TOPE_MS = 6_000L;

    public static void closeQuietly(HttpClient http) {
        if (http == null) return;
        java.lang.reflect.Method shutdown, shutdownNow, awaitTermination;
        try {
            shutdown = HttpClient.class.getMethod("shutdown");
            shutdownNow = HttpClient.class.getMethod("shutdownNow");
            awaitTermination = HttpClient.class.getMethod("awaitTermination", java.time.Duration.class);
        } catch (NoSuchMethodException javaAnteriorA21) {
            return;
        }
        boolean interrumpido = false;
        try {
            shutdown.invoke(http);
            Object termino = awaitTermination.invoke(http, java.time.Duration.ofMillis(CIERRE_TOPE_MS));
            if (!Boolean.TRUE.equals(termino)) {
                shutdownNow.invoke(http);
                awaitTermination.invoke(http, java.time.Duration.ofMillis(200L));
            }
        } catch (Exception e) {
            Throwable causa = e.getCause();
            if (causa instanceof InterruptedException) interrumpido = true;
            try { shutdownNow.invoke(http); } catch (Exception ignored) { }
        } finally {
            if (interrumpido) Thread.currentThread().interrupt();
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
