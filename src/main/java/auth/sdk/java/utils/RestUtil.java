package auth.sdk.java.utils;

import java.io.OutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.logging.Logger;

public class RestUtil {
    private final String authServerUrl;
    private final Logger logger;
    private final Map<String, String> requestHeaders;

    public RestUtil(String authServerUrl, String authorizationHeaderConstant, Logger logger) {
        this.authServerUrl = authServerUrl;
        this.logger = logger;
        this.requestHeaders = new java.util.HashMap<>();
        this.requestHeaders.put("Authorization", authorizationHeaderConstant);
        this.requestHeaders.put("Content-Type", "application/json");
    }

    public HttpURLConnection getRequest(String pathParams, Map<String, String> headers, String data, Map<String, String> cookies) throws Exception {
        String serverUrl = this.authServerUrl;
        if (pathParams != null && !pathParams.isEmpty()) {
            serverUrl += pathParams;
        }

        logger.info("Got <GET> Request for URL and Path Params: " + serverUrl);

        URL url = new URL(serverUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }

        if (cookies != null && !cookies.isEmpty()) {
            StringBuilder cookieBuilder = new StringBuilder();
            for (Map.Entry<String, String> entry : cookies.entrySet()) {
                cookieBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append("; ");
            }
            connection.setRequestProperty("Cookie", cookieBuilder.toString());
        }

        if (data != null) {
            connection.setDoOutput(true);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(data.getBytes());
                os.flush();
            }
        }

        return connection;
    }

    public HttpURLConnection postRequest(String pathParams, Map<String, String> additionalHeaders, String data, Map<String, String> cookies) throws Exception {
        String serverUrl = this.authServerUrl;
        if (pathParams != null && !pathParams.isEmpty()) {
            if (!serverUrl.endsWith("/")) {
                serverUrl += "/";
            }
            serverUrl += pathParams;
        }

        if (additionalHeaders != null) {
            requestHeaders.putAll(additionalHeaders);
        }

        logger.info("Got <POST> Request for URL: " + this.authServerUrl);
        logger.fine("Final request route = " + serverUrl);
        logger.fine("Request Headers = " + requestHeaders);

        URL url = new URL(serverUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);

        // Add headers
        for (Map.Entry<String, String> entry : requestHeaders.entrySet()) {
            connection.setRequestProperty(entry.getKey(), entry.getValue());
        }

        // Add cookies
        if (cookies != null && !cookies.isEmpty()) {
            StringBuilder cookieBuilder = new StringBuilder();
            for (Map.Entry<String, String> entry : cookies.entrySet()) {
                cookieBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append("; ");
            }
            connection.setRequestProperty("Cookie", cookieBuilder.toString());
        }

        if (data != null) {
            try (OutputStream os = connection.getOutputStream()) {
                os.write(data.getBytes());
                os.flush();
            }
        }
        return connection;
    }
}