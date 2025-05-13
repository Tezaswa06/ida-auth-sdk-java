package auth.sdk.java.examples;

import auth.sdk.java.utils.Config;
import com.fasterxml.jackson.databind.JsonNode;
import auth.sdk.java.authenticator.Authenticator;
import auth.sdk.java.models.DemographicsModel;
import auth.sdk.java.utils.ConfigLoader;

import java.util.Optional;

public class DemoAuth {
    public static void main(String[] args) {
        try {
            // Load configuration
            ConfigLoader configLoader = new ConfigLoader();
            Config config = configLoader.loadConfig();
            Authenticator authenticator = new Authenticator(config, null);

            // Create demographics data
            DemographicsModel demographicsData = new DemographicsModel();
            demographicsData.setDob("1992/04/15");

            // Call the authenticator with required and optional parameters
            JsonNode response = (JsonNode) authenticator.auth(
                    "2078529341",  // individualId
                    "UIN",         // individualIdType
                    demographicsData, // demographicData
                    Optional.empty(), // txnId (optional)
                    Optional.empty(), // otpValue (optional)
                    Optional.empty(), // biometrics (optional)
                    true           // consentObtained
            );

            // Print response
            System.out.println("Response: " + response.toPrettyString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}