package com.treeke.asst.service;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Task implements Runnable {

    private Acount account;

    private MailService mailService;

    public Task(Acount account, MailService mailService) {
        this.account = account;
        this.mailService = mailService;
    }

    @Override
    public void run() {
        while (true){
            try {
                Main.start(account.getPhone(), account.getPassword(), account.getEmail());
                mailService.sendSimpleMailMessge(account.getEmail(), "每日上报成功","每日上报成功");
                log.info(account.getPhone() + "：发送邮件成功-------------------------");
            } catch (Throwable e) {
                log.error(account.getPhone() + ":上报错误----------开始重试",e);
                continue;
            }
            break;
        }
    }
}
