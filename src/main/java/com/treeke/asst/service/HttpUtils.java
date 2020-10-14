package com.treeke.asst.service;

import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

/**
 * @ClassName HttpUtils
 * @Description http请求类
 * @Author liuanyicun
 * @Date 2019/2/28 10:49
 * @Version 1.0
 **/
@Slf4j
public class HttpUtils {

    /**
     * 向目的URL发送post请求
     *
     * @param url        目的url
     * @param data 发送的参数
     * @return JSONObject
     */
    public static JSONObject sendPostRequest(String url, HttpHeaders headers, JSONObject data) {
        log.info("http请求url:" + url);
        log.info("请求参数：" + data.toString());
        RestTemplate restTemplate = new RestTemplate();
        //创建请求头
        //HttpHeaders headers = new HttpHeaders();
        //headers.setContentType(MediaType.APPLICATION_JSON);
        //加不加Accept都可以
        //headers.add("Accept", MediaType.APPLICATION_JSON.toString());
        //转字符串
        String jsonString = JSONObject.toJSONString(data);
        HttpEntity<String> entity = new HttpEntity<>(jsonString, headers);
        ResponseEntity<String> responseEntity = restTemplate.postForEntity(url, entity, String.class);
        String responseEntityBody = responseEntity.getBody();
        log.info("返回结果：" + responseEntityBody);
        JSONObject jsonObject =  JSONObject.parseObject(responseEntityBody);
        return jsonObject;
    }

    /**
     * 向目的URL发送get请求
     *
     * @param url        目的url
     * @param jsonObject 发送的参数
     * @return JSONObject
     */
    public static JSONObject sendGetRequest(String url, JSONObject jsonObject) {
        log.info("http请求url:" + url + "-----------------------------------------------------");
        log.info("请求参数：" + jsonObject.toString());
        RestTemplate restTemplate = new RestTemplate();
        //创建请求头
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        //加不加Accept都可以
        headers.add("Accept", MediaType.APPLICATION_JSON.toString());
        //转字符串
        String jsonString = JSONObject.toJSONString(jsonObject);
        HttpEntity<String> entity = new HttpEntity<>(jsonString, headers);
        ResponseEntity<String> responseEntity = restTemplate.getForEntity(url, String.class, entity);
        String responseEntityBody = responseEntity.getBody();
        log.info("返回结果：" + responseEntityBody + "----------------------------------------------");
        return JSONObject.parseObject(responseEntityBody);
    }


}
