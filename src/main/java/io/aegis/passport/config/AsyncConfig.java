package io.aegis.passport.config;

import java.util.concurrent.ThreadPoolExecutor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Bounded executors for async work.
 *
 * <p>Without a bean named {@code applicationTaskExecutor}, Spring falls back to
 * {@code SimpleAsyncTaskExecutor}, which spawns an unbounded thread per task and
 * never recycles them. Every audited action (and every SPA page-view beacon)
 * writes an audit row asynchronously, so under load that default turned into an
 * uncontrolled thread + connection explosion that starved the app and surfaced
 * as 502/503 behind the proxy. Both executors below bound the pools and queue;
 * the audit executor additionally uses {@code CallerRunsPolicy} so audit events
 * are never silently dropped even at the peak.
 */
@Configuration
public class AsyncConfig {

    /** Default executor picked up by plain {@code @Async} (email, violation auto-ban…). */
    @Bean(name = {"applicationTaskExecutor", "taskExecutor"})
    public ThreadPoolTaskExecutor applicationTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(4);
        executor.setMaxPoolSize(8);
        executor.setQueueCapacity(1000);
        executor.setKeepAliveSeconds(60);
        executor.setThreadNamePrefix("app-task-");
        // Email sends and violation recording must not be silently dropped when the
        // queue saturates — the default AbortPolicy would reject the task and the
        // callers that swallow the exception would lose the audit/email silently.
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        executor.initialize();
        return executor;
    }

    /** Audit persistence executor — small and bounded; never lets audit writes starve requests. */
    @Bean(name = "auditExecutor")
    public ThreadPoolTaskExecutor auditExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(2000);
        executor.setKeepAliveSeconds(60);
        executor.setThreadNamePrefix("audit-");
        // If the queue is saturated, persist on the caller thread rather than
        // dropping the audit event.
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(15);
        executor.initialize();
        return executor;
    }
}
