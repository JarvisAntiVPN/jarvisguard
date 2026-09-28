package dev.flamingomg.jarvis.util;

import org.bukkit.Bukkit;
import org.bukkit.entity.Entity;
import org.bukkit.plugin.Plugin;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;

public final class Schedulers {

    private Schedulers() {}

    private static final boolean FOLIA = detectaFolia();

    private static Method mGlobalScheduler;
    private static Method mAsyncScheduler;
    private static Method mEntityScheduler;
    private static Method mGlobalRun;
    private static Method mGlobalAtFixedRate;
    private static Method mAsyncRunNow;
    private static Method mAsyncDelayed;
    private static Method mAsyncAtFixedRate;
    private static Method mEntityRun;

    static {
        if (FOLIA) resuelve();
    }

    private static boolean detectaFolia() {
        try {
            Class.forName("io.papermc.paper.threadedregions.RegionizedServer");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private static void resuelve() {
        try {
            Class<?> consumer = java.util.function.Consumer.class;
            mGlobalScheduler = Bukkit.class.getMethod("getGlobalRegionScheduler");
            mAsyncScheduler  = Bukkit.class.getMethod("getAsyncScheduler");
            mEntityScheduler = Entity.class.getMethod("getScheduler");

            Class<?> global = mGlobalScheduler.getReturnType();
            mGlobalRun         = global.getMethod("run", Plugin.class, consumer);
            mGlobalAtFixedRate = global.getMethod("runAtFixedRate", Plugin.class, consumer, long.class, long.class);

            Class<?> async = mAsyncScheduler.getReturnType();
            mAsyncRunNow      = async.getMethod("runNow", Plugin.class, consumer);
            mAsyncDelayed     = async.getMethod("runDelayed", Plugin.class, consumer, long.class, TimeUnit.class);
            mAsyncAtFixedRate = async.getMethod("runAtFixedRate", Plugin.class, consumer, long.class, long.class, TimeUnit.class);

            Class<?> entity = mEntityScheduler.getReturnType();
            mEntityRun = entity.getMethod("run", Plugin.class, consumer, Runnable.class);
        } catch (Throwable t) {
            mGlobalRun = null;
        }
    }

    public static boolean folia() { return FOLIA; }

    public static boolean disponible() {
        return !FOLIA || (mGlobalRun != null && mAsyncRunNow != null && mEntityRun != null
                       && mGlobalAtFixedRate != null && mAsyncDelayed != null && mAsyncAtFixedRate != null);
    }

    public static void global(Plugin plugin, Runnable tarea) {
        if (!FOLIA) { Bukkit.getScheduler().runTask(plugin, tarea); return; }
        invocaConTarea(mGlobalScheduler, mGlobalRun, plugin, tarea);
    }

    public static void globalRepetida(Plugin plugin, Runnable tarea, long retardoTicks, long periodoTicks) {
        if (!FOLIA) { Bukkit.getScheduler().runTaskTimer(plugin, tarea, retardoTicks, periodoTicks); return; }
        long retardo = Math.max(1L, retardoTicks);
        long periodo = Math.max(1L, periodoTicks);
        try {
            Object sched = mGlobalScheduler.invoke(null);
            mGlobalAtFixedRate.invoke(sched, plugin, consumidor(tarea), retardo, periodo);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw fallo(e);
        }
    }

    public static void async(Plugin plugin, Runnable tarea) {
        if (!FOLIA) { Bukkit.getScheduler().runTaskAsynchronously(plugin, tarea); return; }
        invocaConTarea(mAsyncScheduler, mAsyncRunNow, plugin, tarea);
    }

    public static void asyncRetrasada(Plugin plugin, Runnable tarea, long retardoTicks) {
        if (!FOLIA) { Bukkit.getScheduler().runTaskLaterAsynchronously(plugin, tarea, retardoTicks); return; }
        try {
            Object sched = mAsyncScheduler.invoke(null);
            mAsyncDelayed.invoke(sched, plugin, consumidor(tarea),
                    Math.max(1L, aMillis(retardoTicks)), TimeUnit.MILLISECONDS);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw fallo(e);
        }
    }

    public static Runnable asyncRepetida(Plugin plugin, Runnable tarea, long retardoTicks, long periodoTicks) {
        if (!FOLIA) {
            org.bukkit.scheduler.BukkitTask t =
                    Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, tarea, retardoTicks, periodoTicks);
            return t::cancel;
        }
        try {
            Object sched = mAsyncScheduler.invoke(null);
            Object tarea2 = mAsyncAtFixedRate.invoke(sched, plugin, consumidor(tarea),
                    Math.max(1L, aMillis(retardoTicks)), Math.max(1L, aMillis(periodoTicks)), TimeUnit.MILLISECONDS);
            if (tarea2 == null) return () -> { };
            java.lang.reflect.Method cancel = tarea2.getClass().getMethod("cancel");
            cancel.setAccessible(true);
            return () -> { try { cancel.invoke(tarea2); } catch (Exception ignored) { } };
        } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw fallo(e instanceof NoSuchMethodException ? new IllegalStateException(e) : (Exception) e);
        }
    }

    public static void deEntidad(Plugin plugin, Entity entidad, Runnable tarea) {
        if (!FOLIA) {
            if (Bukkit.isPrimaryThread()) tarea.run();
            else Bukkit.getScheduler().runTask(plugin, tarea);
            return;
        }
        try {
            Object sched = mEntityScheduler.invoke(entidad);
            if (sched == null) return;
            mEntityRun.invoke(sched, plugin, consumidor(tarea), (Runnable) () -> {  });
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw fallo(e);
        }
    }

    public static void aRemitente(Plugin plugin, org.bukkit.command.CommandSender remitente, Runnable tarea) {
        if (remitente instanceof Entity e) deEntidad(plugin, e, tarea);
        else global(plugin, tarea);
    }

    private static java.util.function.Consumer<Object> consumidor(Runnable tarea) {
        return ignorado -> tarea.run();
    }

    static long aMillis(long ticks) { return Math.max(0L, ticks) * 50L; }

    private static void invocaConTarea(Method getter, Method run, Plugin plugin, Runnable tarea) {
        try {
            Object sched = getter.invoke(null);
            run.invoke(sched, plugin, consumidor(tarea));
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw fallo(e);
        }
    }

    private static RuntimeException fallo(Exception e) {
        Throwable causa = (e instanceof InvocationTargetException ite && ite.getCause() != null) ? ite.getCause() : e;
        if (causa instanceof RuntimeException re) return re;
        return new IllegalStateException("Could not schedule the task on Folia", causa);
    }
}
