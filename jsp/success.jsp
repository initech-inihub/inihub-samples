<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.io.*" %>
<%@ page import="java.net.URL" %>
<%@ page import="java.net.HttpURLConnection" %>
<%@ page import="java.util.Base64" %>
<%@ page import="java.nio.charset.StandardCharsets" %>
<%@ page import="javax.crypto.Cipher" %>
<%@ page import="javax.crypto.spec.SecretKeySpec" %>
<%@ page import="javax.crypto.spec.IvParameterSpec" %>
<%@ page import="org.json.simple.parser.JSONParser" %>
<%@ page import="org.json.simple.JSONObject" %>
<%!
    /**
     * 데이터 복호화 함수
     * @param encrypted 암호화된 데이터
     * @param key 복호화 KEY
     * @param iv 복호화 IV
     * @return 복호화된 데이터
     */
    private String decrypt(String encrypted, String key, String iv) {

        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(
                    Cipher.DECRYPT_MODE
                    , new SecretKeySpec(Base64.getDecoder().decode(key.getBytes()), "AES")
                    , new IvParameterSpec(Base64.getDecoder().decode(iv.getBytes())));

            byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(encrypted.getBytes()));
            return new String(bytes, StandardCharsets.UTF_8);

        } catch (Exception ex) {
            ex.printStackTrace();
            return "decrypt-fail!";
        }
    }
%>
<%
    /* ================================================================================
    | 인증완료 결과로 발급받은 인증토큰(authToken) 검증을 요청하고 결과로 사용자 정보를 획득 한다.
    ================================================================================ */
    String clientId = "${이용기관 어플리케이션 ID}";
    String appKey   = "${이용기관 어플리케이션 APP-KEY}";
    String inihubApiUrl = "${인증토큰 검증 API 주소}";
    String aesKey = "${데이터 복호화 KEY}";
    String aesIv  = "${데이터 복호화 IV }";

    /* ------------------------------------
    | 인증토큰(authToken) 검증 API 호출
    ------------------------------------ */
    URL url = new URL(inihubApiUrl);

    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestProperty("Authorization", "Bearer " + appKey);
    connection.setRequestProperty("Content-Type" , "application/json; charset=UTF-8");
    connection.setRequestProperty("Client-Id", clientId);
    connection.setRequestMethod  ("POST");
    connection.setDoOutput(true);

    String authToken = request.getParameter("authToken");
    JSONObject obj = new JSONObject();
    obj.put("authToken", authToken);

    OutputStream outputStream = connection.getOutputStream();
    outputStream.write(obj.toString().getBytes(StandardCharsets.UTF_8));

    int code = connection.getResponseCode();
    boolean isSuccess = code == 200;

    InputStream responseStream = isSuccess ? connection.getInputStream() : connection.getErrorStream();
    BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));

    StringBuilder resultDataString = new StringBuilder();
    String intpuList;
    while ((intpuList = in.readLine()) != null) {
        resultDataString.append(intpuList);
    }

    /* ------------------------------------
    | 응답 데이터 파싱(JSON)
    ------------------------------------ */
    JSONParser jsonParser = new JSONParser();
    JSONObject resultObj  = (JSONObject) jsonParser.parse(resultDataString.toString());
    String resCode = resultObj.get("resCode").toString();

    responseStream.close();
%>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta http-equiv="ScreenOrientation" content="autoRotate:disabled">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>이니허브 인증토큰 검증 샘플</title>
    <style>
        table th {
            width: 120px;
            text-align: right;
        }

        table td {
            padding-left: 5px;
        }
    </style>
</head>
<body>
<%
    if (resCode.equals("1200")) {
        String payload = resultObj.get("payload").toString();
        JSONObject payloadObj = (JSONObject) jsonParser.parse(payload);
%>
    <h3>인증토큰 검증 성공</h3>
    <p>이름 :
        <%= decrypt((String) payloadObj.get("uname")    , aesKey, aesIv) %>
    </p>
    <p>생년월일 :
        <%= decrypt((String) payloadObj.get("ubirthday"), aesKey, aesIv) %>
    </p>
    <p>성별 :
        <%= decrypt((String) payloadObj.get("ugender")  , aesKey, aesIv) %>
    </p>
    <p>휴대폰번호 :
        <%= decrypt((String) payloadObj.get("uphone")   , aesKey, aesIv) %>
    </p>
    <p>연계정보(CI) :
        <%= decrypt((String) payloadObj.get("uci")      , aesKey, aesIv) %>
    </p>
<%
    } else {
%>
    <h3>인증토큰 검증 실패</h3>
    <p>[<%= resCode %>] <%= resultObj.get("errorMessage") %></p>
<%
    }
%>
</body>
</html>