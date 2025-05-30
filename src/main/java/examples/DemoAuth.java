package examples;

import auth.sdk.java.models.DemographicsModel;
import auth.sdk.java.models.IdentityInfo;
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
            DemographicsModel demographicsData = new DemographicsModel();
            demographicsData.setDob("1992/04/15");
            demographicsData.setEmailId("ESignet_AddIdentity_BioAuth_smoke_Pos@mosip.net");

        // Set name
            IdentityInfo nameInfo = new IdentityInfo();
            nameInfo.setLanguage("eng");
            nameInfo.setValue("TEST_FULLNAMEeng");
            demographicsData.getName().add(nameInfo);

            // Set gender
            IdentityInfo genderInfo = new IdentityInfo();
            genderInfo.setLanguage("eng");
            genderInfo.setValue("MLEeng");
            demographicsData.getGender().add(genderInfo);

              // Set full address
//            IdentityInfo addressInfo = new IdentityInfo();
//            addressInfo.setLanguage("eng");
//            addressInfo.setValue("TEST_ADDRESSLINE1eng, TEST_ADDRESSLINE2eng, TEST_ADDRESSLINE3eng");
//            demographicsData.getFullAddress().add(addressInfo);

            //demographicsData.setPhoneNumber("1234567890"); // Set phone number
            // Perform authentication
            Map<String, Object> response = authenticator.auth(
                    "8536475201", // individualId
                    "UIN",             // individualIdType
                    demographicsData  , // demographicData
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