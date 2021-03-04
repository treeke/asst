package com.treeke.asst.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledThreadPoolExecutor;

@Slf4j
@Component
public class TaskManager {

    @Autowired
    private AcountManager acountManager;

    @Autowired
    private ScheduledThreadPoolExecutor scheduledThreadPoolExecutor;

    @Autowired
    private MailService mailService;

    //@Scheduled(cron = "0 0/5 * * * ? ")
    @Scheduled(cron = "0 0 1 * * ?")
    public void configureTasks() {
        Map<String, Acount> manager = acountManager.getManager();
        manager.forEach((k,v)->{
            Task task = new Task(v, mailService);
            scheduledThreadPoolExecutor.execute(task);
        });

    }
}
