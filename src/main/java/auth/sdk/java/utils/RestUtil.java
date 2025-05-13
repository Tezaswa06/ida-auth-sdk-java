package auth.sdk.java.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

public class RestUtil {
    private final String authServerUrl;
    private final Map<String, String> requestHeaders;
    private final Logger logger;

    public RestUtil(String authServerUrl, String authorizationHeaderConstant, Logger logger) {
        this.authServerUrl = authServerUrl;
        this.requestHeaders = Map.of(
                "Authorization", authorizationHeaderConstant,
                "Content-Type", "application/json"
        );
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

    public Map<String, Object> postRequest(String pathParams, Map<String, String> additionalHeaders, byte[] data, Map<String, String> cookies) throws Exception {
        String serverUrl = authServerUrl;
        if (pathParams != null) {
            if (!serverUrl.endsWith("/")) {
                serverUrl += "/";
            }
            serverUrl += pathParams;
        }

        HttpURLConnection conn = (HttpURLConnection) new URL(serverUrl).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);

        // Merge headers
        requestHeaders.forEach(conn::setRequestProperty);
        if (additionalHeaders != null) {
            additionalHeaders.forEach(conn::setRequestProperty);
        }

        if (cookies != null) {
            conn.setRequestProperty("Cookie", String.join("; ", cookies.values()));
        }

        logger.info("Got <POST> Request for URL: {}", serverUrl);
        logger.debug("Request Headers: {}", conn.getRequestProperties());

        if (data != null) {
            try (OutputStream os = conn.getOutputStream()) {
                os.write(data);
            }
        }

        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(conn.getInputStream(), Map.class);
    }
}