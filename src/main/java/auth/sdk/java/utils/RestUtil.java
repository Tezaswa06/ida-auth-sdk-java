package auth.sdk.java.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.slf4j.Logger;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RestUtil {
    private final String authServerUrl;
    private final Map<String, String> requestHeaders;
    private final Logger logger;

    public RestUtil(String authServerUrl, String authorizationHeaderConstant, Logger logger) {
        this.authServerUrl = authServerUrl;
        this.requestHeaders = new HashMap<>(); // Use a mutable map
        this.requestHeaders.put("Authorization", authorizationHeaderConstant);
        this.requestHeaders.put("Content-Type", "application/json");
        this.logger = logger;
    }

    public Map<String, Object> getRequest(String pathParams, Map<String, String> headers, byte[] data, Map<String, String> cookies) throws Exception {
        String serverUrl = authServerUrl;
        if (pathParams != null) {
            serverUrl += pathParams;
        }
        logger.info("Got <GET> Request for URL and Path Params: {}", serverUrl);

        HttpURLConnection conn = (HttpURLConnection) new URL(serverUrl).openConnection();
        conn.setRequestMethod("GET");
        headers.forEach(conn::setRequestProperty);
        if (data != null) {
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(data);
            }
        }
        if (cookies != null) {
            conn.setRequestProperty("Cookie", String.join("; ", cookies.values()));
        }

        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(conn.getInputStream(), Map.class);
    }


    public Map<String, Object> postRequest(String pathParams, Map<String, String> headers, byte[] body, String token) throws Exception {
        String url = authServerUrl + (pathParams != null ? "/" + pathParams : "");
        logger.info("POST Request URL: " + url);

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost httpPost = new HttpPost(url);

            // Set headers
            if (headers != null) {
                headers.forEach(httpPost::addHeader);
            }
            if (token != null && !token.isEmpty()) {
                httpPost.addHeader("Authorization", "Bearer " + token);
            }

            // Log headers
            logger.debug("Request Headers: " + headers);

            // Set body
            if (body != null) {
                httpPost.setEntity(new ByteArrayEntity(body, null));
            }

            System.out.println("POST URL: " + url);
            System.out.println("Payload: " + new String(body, StandardCharsets.UTF_8));
            System.out.println("Headers: " + headers);

            // Execute request
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                int statusCode = response.getCode();
                String responseString = new String(response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);

                logger.info("Response Status: " + statusCode);
                logger.info("Response Body: " + responseString);

                // Convert response to Map
                ObjectMapper objectMapper = new ObjectMapper();
                return objectMapper.readValue(responseString, Map.class);
            }
        }
        }
}