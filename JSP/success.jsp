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
<%

    /* ================================================================================
    | 발급 받은 인증토큰 검증을 요청한다. 인증토큰이 유효한 경우 사용자 인증 데이터가 리턴된다.
    ================================================================================ */
    String authApiUrl = "https://dat-stg.inihub.biz:8000/auth/oauth/v2/token";
    String clientId = "${이용기관 어플리케이션 ID}";
    String secret   = "${이용기관 어플리케이션 SECRET}";
    String verifyApiUrl = "https://dat-stg.inihub.biz:8000/api/v1/ezauth/authtoken/verify.do";
    String aesKey = "${데이터 복호화 KEY}";
    String aesIv  = "${데이터 복호화 IV }";

    // 접근토큰(accessToken) 발급 요청
    String accessToken = getAccessToken(authApiUrl, clientId, secret);
    System.out.println("accessToken -> [" + accessToken + "]");

    // 인증토큰(authToken) 검증 요청
    JSONObject resultObj = verifyAuthToken(verifyApiUrl, accessToken, request.getParameter("authToken"));
    System.out.println("authToken-verify-result -> [" + resultObj.toString() + "]");
%>
<%!
    /**
     * 접근토큰 발급 요청
     * @param apiUrl 접근토큰 발급요청 API 주소
     * @param clientId 이용기관 어플리케이션 ID
     * @param secret 이용기관 어플리케이션 인증을 위한 SECERT
     * @return 접근토큰
     * @throws Exception
     */
    private String getAccessToken(String apiUrl, String clientId, String secret) throws Exception {

        String contentType   = "application/x-www-form-urlencoded; charset=UTF-8";
        String credentials   = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
        String authorization = "Basic " + credentials;
        JSONObject resultObj = post(apiUrl, contentType, authorization, "grant_type=client_credentials");
        return resultObj.get("access_token").toString();
    }

    /**
     * 인증토큰 검증 요청
     * @param apiUrl 인증토큰 검증요청 API 주소
     * @param accessToken 접근토큰
     * @param authToken 인증토큰
     * @return 인증토큰 검증결과
     * @throws Exception
     */
    private JSONObject verifyAuthToken(String apiUrl, String accessToken, String authToken) throws Exception {

        String contentType    = "application/json; charset=UTF-8";
        String authorization  = "Bearer " + accessToken;
        JSONObject requestObj = new JSONObject();
        requestObj.put("authToken", authToken);
        return post(apiUrl, contentType, authorization, requestObj.toString());
    }

    private JSONObject post(String endpoint, String contentType, String authorization, String requestBody) throws Exception {

        HttpURLConnection connection = (HttpURLConnection) new URL(endpoint).openConnection();
        connection.setRequestProperty("Content-Type" , contentType  );
        connection.setRequestProperty("Authorization", authorization);
        connection.setRequestMethod  ("POST");
        connection.setDoOutput(true);

        OutputStream outputStream = connection.getOutputStream();
        outputStream.write(requestBody.getBytes(StandardCharsets.UTF_8));

        int code = connection.getResponseCode();
        boolean isSuccess = code == 200;

        InputStream responseStream = isSuccess ? connection.getInputStream() : connection.getErrorStream();
        Reader reader = new InputStreamReader(responseStream, StandardCharsets.UTF_8);

        JSONParser jsonParser = new JSONParser();
        JSONObject resultObject = (JSONObject) jsonParser.parse(reader);
        responseStream.close();

        return resultObject;
    }

    /**
     * 데이터 복호화 함수
     * @param encrypted 암호화된 데이터
     * @param key 복호화 KEY
     * @param iv 복호화 IV
     * @return 복호화된 데이터
     */
    private String decrypt(String encrypted, String key, String iv) {
        if (encrypted == null || encrypted.isEmpty()) {
            return "";
        }

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
    if (resultObj.get("resCode").toString().equals("1200")) {
        String payload = resultObj.get("payload").toString();
        JSONObject payloadObj = (JSONObject) new JSONParser().parse(payload);
%>
    <h3>인증토큰 검증 성공</h3>
    <h4>간편인증 결과</h4>
    <p>이름 :
        <%= decrypt((String) payloadObj.get("uname"     ), aesKey, aesIv) %>
    </p>
    <p>생년월일 :
        <%= decrypt((String) payloadObj.get("ubirthday" ), aesKey, aesIv) %>
    </p>
    <p>성별 :
        <%= decrypt((String) payloadObj.get("usex"      ), aesKey, aesIv) %>
    </p>
    <p>외국인여부 :
        <%= decrypt((String) payloadObj.get("uforeigner"), aesKey, aesIv) %>
    </p>
    <p>휴대폰번호 :
        <%= decrypt((String) payloadObj.get("uphone"    ), aesKey, aesIv) %>
    </p>
    <p>연계정보(CI) :
        <%= decrypt((String) payloadObj.get("uci"       ), aesKey, aesIv) %>
    </p>
    <h4>공동인증서 및 금융인증서 결과</h4>
    <p> 발급자:
        <%= payloadObj.get("issuerDn") %>
    </p>
    <p> 발급대상:
        <%= payloadObj.get("subjectDn") %>
    </p>
    <p> R-Value:
        <%= payloadObj.get("rValue") %>
    </p>
    <p> VID:
        <%= payloadObj.get("vid") %>
    </p>
    <p> VID 해쉬 알고리즘:
        <%= payloadObj.get("vidHashAlg") %>
    </p>
    <p> 인증서 시리얼 번호:
        <%= payloadObj.get("serial") %>
    </p>
    <p> 공개키:
        <%= payloadObj.get("publicKey") %>
    </p>
    <p> 원문:
        <%= payloadObj.get("plainText") %>
    </p>
    <p> 전자서명 값:
        <%= payloadObj.get("signature") %>
    </p>
    <p> 전자서명 데이터:
        <%= payloadObj.get("signedData") %>
    </p>
<%
    } else {
%>
    <h3>인증토큰 검증 실패</h3>
    <p>[<%= resultObj.get("resCode").toString() %>] <%= resultObj.get("errorMessage") %></p>
<%
    }
%>
</body>
</html>
