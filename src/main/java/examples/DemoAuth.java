package examples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import auth.sdk.java.authenticator.Authenticator;
import auth.sdk.java.utils.ConfigLoader;

import java.util.Map;
import java.util.Optional;

public class DemoAuth {
    public static void main(String[] args) {
        try {
            // Load configuration
            ConfigLoader configLoader = new ConfigLoader();
            Authenticator authenticator = new Authenticator(configLoader.loadConfig(), null);

            // Perform authentication
            Map<String, Object> response = authenticator.auth(
                    "8536475201", // individualId
                    "UIN",              // individualIdType
                    null,               // demographicData
                    Optional.empty(),   // txnId
                    Optional.empty(),   // otpValue
                    Optional.empty(),   // biometrics
                    true                // consentObtained
            );

            // Convert response to JsonNode
            ObjectMapper mapper = new ObjectMapper();
            JsonNode responseNode = mapper.convertValue(response, JsonNode.class);

            // Print response
            System.out.println("Response: " + responseNode.toPrettyString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}