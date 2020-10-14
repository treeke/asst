package com.treeke.asst.controller;

import com.alibaba.fastjson.JSONObject;
import com.treeke.asst.service.Acount;
import com.treeke.asst.service.AcountManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/acount")
@Slf4j
public class AcountController {

    @Autowired
    private AcountManager acountManager;

    @PostMapping("/add")
    public JSONObject addAcount(@RequestBody Acount acount){
        acountManager.addAccount(acount);
        log.info("添加账号[{}]成功", acount.getPhone());
        JSONObject response = new JSONObject();
        response.put("code",200);
        response.put("msg","成功");
        return response;
    }

    @GetMapping("/query")
    public Map query(){
        return acountManager.getManager();
    }

}
