package auth.sdk.java.examples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import auth.sdk.java.authenticator.Authenticator;
import auth.sdk.java.models.DemographicsModel;
import auth.sdk.java.models.BiometricModel;
import auth.sdk.java.utils.ConfigLoader;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

public class OtpVerify {
    public static void main(String[] args) {
        try {
            // Load configuration
            ConfigLoader configLoader = new ConfigLoader();
            Authenticator authenticator = new Authenticator(configLoader.loadConfig(), null);

            // Perform KYC authentication with optional parameters
            Map<String, Object> response = authenticator.kyc(
                    "8300715076",         // txnId
                    "2078529341",         // individualId
                    "UIN",                // individualIdType
                    Optional.empty(),     // demographicData (optional)
                    Optional.empty(),     // otpValue (optional)
                    Optional.empty(),     // biometrics (optional)
                    true                  // consent
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

            // Print response status
            System.out.println("Response status: 200");

            // Decrypt and print the response
            Map<String, Object> decryptedResponse = authenticator.decryptResponse(response);
            System.out.println("Decrypted response: " + mapper.writeValueAsString(decryptedResponse));

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}