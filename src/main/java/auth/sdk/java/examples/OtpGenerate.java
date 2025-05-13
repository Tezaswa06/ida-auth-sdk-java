package auth.sdk.java.examples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import auth.sdk.java.authenticator.Authenticator;
import auth.sdk.java.utils.ConfigLoader;

import java.io.IOException;
import java.util.Map;

public class OtpGenerate {
    public static void main(String[] args) {
        try {
            // Load configuration
            ConfigLoader configLoader = new ConfigLoader();
            Authenticator authenticator = new Authenticator(configLoader.loadConfig(), null);

            // Perform OTP generation
            Map<String, Object> response = authenticator.genOtp(
                    "4370296312658178", // individual_id
                    "VID",              // individual_id_type
                    "1234567890",       // txnId
                    true,               // email
                    true                // phone
            );

            // Convert response to JsonNode for easier processing
            ObjectMapper mapper = new ObjectMapper();
            JsonNode responseNode = mapper.convertValue(response, JsonNode.class);

            // Check for errors
            if (responseNode.has("errors")) {
                for (JsonNode error : responseNode.get("errors")) {
                    System.out.println(error.get("errorCode").asText() + " : " + error.get("errorMessage").asText());
                }
                System.exit(1);
            }

            // Print response
            System.out.println("Response status: 200");
            System.out.println("Response body: " + responseNode.toPrettyString());

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}