package com.treeke.asst;

import com.treeke.asst.service.Acount;
import com.treeke.asst.service.AcountManager;
import com.treeke.asst.service.MailService;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

@SpringBootApplication
@EnableScheduling
public class AsstApplication implements ApplicationRunner {

    @Autowired
    private AcountManager acountManager;

    @Autowired
    private MailService mailService;

    public static void main(String[] args) {
        SpringApplication.run(AsstApplication.class, args);
    }

    @Bean
    public ScheduledThreadPoolExecutor createExecutor(){
        ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(5);
        scheduledThreadPoolExecutor.setThreadFactory(new ThreadFactory() {
            private AtomicInteger atomicInteger = new AtomicInteger(0);
            @Override
            public Thread newThread(@NotNull Runnable r) {
                Thread thread = new Thread(r);
                thread.setName("业务处理线程-pool1-" + atomicInteger.getAndIncrement());
                thread.setPriority(5);
                return thread;
            }
        });
        return scheduledThreadPoolExecutor;
    }

    @Override
    public void run(ApplicationArguments args) {
        Acount account = new Acount();
        account.setEmail("1127787372@qq.com");
        account.setPassword("199588");
        account.setPhone("18011572963");
        acountManager.addAccount(account);
    }
}
