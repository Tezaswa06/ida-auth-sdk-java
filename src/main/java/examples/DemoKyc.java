package examples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import auth.sdk.java.authenticator.Authenticator;
import auth.sdk.java.models.DemographicsModel;
import auth.sdk.java.models.IdentityInfo;
import auth.sdk.java.utils.ConfigLoader;

import java.util.Collections;
import java.util.Optional;

public class DemoKyc {
    public static void main(String[] args) {
        try {
            // Load configuration
            ConfigLoader configLoader = new ConfigLoader();
            Authenticator authenticator = new Authenticator(configLoader.loadConfig(), null);

            // Create demographics data
            IdentityInfo nameInfo = new IdentityInfo();
            nameInfo.setLanguage("eng");
            nameInfo.setValue("jevan mksm");

            DemographicsModel demographicsData = new DemographicsModel();
            demographicsData.setName(Collections.singletonList(nameInfo));

            // Log demographics data
            System.out.println("Demographics data: " + demographicsData);

            // Perform KYC authentication
            String txnId = "1234567890"; // Example transaction ID
            JsonNode response = (JsonNode) authenticator.kyc(
                    txnId,                              // txnId
                    "4370296312658178",                 // individual_id
                    "VID",                              // individual_id_type
                    Optional.of(demographicsData),      // demographic_data
                    Optional.empty(),                   // otpValue
                    Optional.empty(),                   // biometrics
                    true                                // consent
            );

            // Check for errors in the response
            if (response != null && response.has("errors")) {
                JsonNode errors = response.get("errors");
                for (JsonNode error : errors) {
                    System.out.println(error.get("errorCode").asText() + " : " + error.get("errorMessage").asText());
                }
                System.exit(1);
            }

            // Print response
            System.out.println("Response: " + response.toPrettyString());

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}