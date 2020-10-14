package com.treeke.asst.service;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AcountManager {
    private static final ConcurrentHashMap<String, Acount> map = new ConcurrentHashMap();

    public void addAccount(Acount account){
        map.put(account.getPhone(), account);
    }
    public Map<String, Acount> getManager(){
        return map;
    }
}
