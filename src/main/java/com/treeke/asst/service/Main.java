package com.treeke.asst.service;

import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Date;

@Slf4j
@Component
public class Main {

    private static final String URL1 = "https://asst.cetccloud.com/oort/oortcloud-sso/sso/v1/slideverify";
    private static final String URL2 = "https://asst.cetccloud.com/oort/oortcloud-sso/cetc/v1/getUserInfo";
    private static final String URL3 = "https://asst.cetccloud.com/ncov/login";
    private static final String URL4 = "https://asst.cetccloud.com/oort/oortcloud-sso/sso/v1/getCaptcha";
    private static final String URL5 = "https://asst.cetccloud.com/oort/oortcloud-2019-ncov-report/2019-nCov/report/everyday_report";
    public static void main(String[] args) throws IOException {
        start("18683674169", "yan87562958","pickyourself@163.com");
        //start("18011572963", "199588", "pickyourself@163.com");
        //start("15828580081", "lesile520 ");
    }

    public static void start(String phone, String password, String email) throws IOException {
        String token = null;
        while (true){
            String slideID = getSlideID();
            if(slideID == null){
                continue;
            }
            token = getToken(slideID,phone,password);
            if(token == null){
                continue;
            }
            break;
        }
        //getUserInfo(phone, token);

        report(phone, token);
        log.info("phone:[{}],Date:[{}]上报成功----------------------------------------------------------------", phone, new Date());
    }

    private static void report(String phone, String token) {
        JSONObject param = createParam(phone, token);
        HttpHeaders header = createHeader(token);
        while(true){
            JSONObject jsonObject = HttpUtils.sendPostRequest(URL5, header, param);
            Integer code = Integer.valueOf(jsonObject.get("code")+"");
            if(code.equals(70001)){
                break;
            }
            if(code != 200){
                continue;
            }
            break;
        }
    }

    private static JSONObject getUserInfo(String phone, String token) {
        JSONObject param = new JSONObject();
        param.put("accessToken",token);
        param.put("oort_phone",phone);
        HttpHeaders header = createHeader(token);
        while(true){
            JSONObject jsonObject = HttpUtils.sendPostRequest(URL2, header, param);
            Integer code = Integer.valueOf(jsonObject.get("code")+"");
            if(code != 200){
                continue;
            }
            JSONObject data = JSONObject.parseObject(JSONObject.toJSONString(jsonObject.get("data")));
            String result = JSONObject.toJSONString(data.get("userInfo"));
            JSONObject userInfo = JSONObject.parseObject(result);
            String idCard = String.valueOf(userInfo.get("IDCard"));
            String uuid = String.valueOf(userInfo.get("UUID"));
            String userName = String.valueOf(userInfo.get("UserName"));
            return userInfo;
        }
    }

    private static JSONObject createParam(String phone, String token) {
        JSONObject trafficData = new JSONObject();
        trafficData.put("bike", 0);
        trafficData.put("bike_way", "");
        trafficData.put("bus", 0);
        trafficData.put("bus_number", "");
        trafficData.put("car", 0);
        trafficData.put("car_way", "");
        trafficData.put("metro", 0);
        trafficData.put("metro_number", "");
        trafficData.put("other", 0);
        trafficData.put("other_way", "");
        trafficData.put("phone", phone);
        trafficData.put("walk", 0);
        trafficData.put("walk_way", "");

        JSONObject physicalData = new JSONObject();
        physicalData.put("phone",phone);
        physicalData.put("type1",0);
        physicalData.put("type1_state","");
        physicalData.put("type2",0);
        physicalData.put("type3",0);
        physicalData.put("type4",0);
        physicalData.put("type5",0);
        physicalData.put("type6",0);
        physicalData.put("type7",0);
        physicalData.put("type7_state","");

        JSONObject trackData = new JSONObject();
        trackData.put("phone",phone);
        trackData.put("tracks","[]");

        JSONObject data = new JSONObject();
        data.put("Traffic_data", trafficData);
        data.put("accessToken", token);
        data.put("phone", phone);
        data.put("physical_data", physicalData);
        data.put("touch", 0);
        data.put("track_data", trackData);
        data.put("work_way", 0);

        return data;
    }

    private static String getToken(String slideID, String phone, String password) throws IOException {
        OkHttpClient client = new OkHttpClient().newBuilder()
                .build();
        MultipartBody body = new MultipartBody.Builder().setType(MultipartBody.FORM)
                .addFormDataPart("mobile", phone)
                .addFormDataPart("password", CsoftSecurityUtil.getSign(password))
                .addFormDataPart("client", "h5")
                .addFormDataPart("slideID", slideID)
                .build();
        Request request = new Request.Builder()
                .url(URL3)
                .method("POST", body)
                .addHeader("Content-Type", "multipart/form-data")
                .build();
        while (true){
            Response response = client.newCall(request).execute();
            ResponseBody body1 = response.body();
            String res = new String(body1.bytes(), "UTF-8");

            log.info("返回结果：" + res + "----------------------------------------------");
            JSONObject json =  JSONObject.parseObject(res);
            Integer code = Integer.valueOf(json.get("code")+"");
            if(code != 200){
                continue;
            }
            JSONObject data = JSONObject.parseObject(JSONObject.toJSONString(json.get("data")));
            String userInfo = JSONObject.toJSONString(data.get("userInfo"));
            JSONObject result = JSONObject.parseObject(userInfo);
            String accessToken = String.valueOf(result.get("accessToken"));
            return accessToken;
        }
    }

    private static String getSlideID(){
        HttpHeaders header = createHeader(null);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("model","login");
        JSONObject jsonObject1 = HttpUtils.sendPostRequest(URL4, header, jsonObject);
        Integer code1 = Integer.valueOf(jsonObject1.get("code")+"");
        if(code1 != 200){
            return null;
        }
        JSONObject captcha = JSONObject.parseObject(JSONObject.toJSONString(jsonObject1.get("data")));
        captcha.put("xpos",150);
        captcha.remove("ypos");
        JSONObject response = HttpUtils.sendPostRequest(URL1, header, captcha);
        Integer code2 = Integer.valueOf(response.get("code")+"");
        if(code2 != 200){
            return null;
        }
        Object data = response.get("data");
        if(data != null){
            return null;
        }
        return String.valueOf(captcha.get("slideID"));
    }

    private static HttpHeaders createHeader(String accessToken) {
        //创建请求头
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        //加不加Accept都可以
        headers.add("Accept", MediaType.APPLICATION_JSON.toString());
        headers.add("applyID", "df626fdc9ad84d3a95633c10124df358");
        headers.add("secretKey", "D8FE427008F065C1B781917E82E1EC1E");
        headers.add("requestType", "zuul");
        headers.add("accessToken", accessToken);
        return headers;
    }
}
