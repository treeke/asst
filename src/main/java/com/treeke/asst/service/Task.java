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
                String msg = Main.start(account.getPhone(), account.getPassword(), account.getEmail());
                if (null != account.getEmail() && !"70001".equals(msg)) {
                    mailService.sendSimpleMailMessge(account.getEmail(), "每日上报结果： " + msg, "每日上报结果： " + msg);
                    log.info(account.getPhone() + "：发送邮件成功-------------------------");
                } else {
                    log.info(account.getPhone() + "：未配置邮箱/已经上报过了，不用发送邮件-------------------------");
                }
            } catch (Throwable e) {
                log.error(account.getPhone() + ":上报错误----------开始重试",e);
                continue;
            }
            break;
        }
    }
}
