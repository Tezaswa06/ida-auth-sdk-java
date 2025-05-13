package auth.sdk.java.models;

import lombok.Getter;
import lombok.Setter;

import java.util.*;

@Getter
@Setter
public class DemographicsModel {
    private String age = "";
    private String dob = "";
    private List<IdentityInfo> name = new ArrayList<>();
    private List<IdentityInfo> dobType = new ArrayList<>();
    private List<IdentityInfo> gender = new ArrayList<>();
    private String phoneNumber = "";
    private String emailId = "";
    private List<IdentityInfo> addressLine1 = new ArrayList<>();
    private List<IdentityInfo> addressLine2 = new ArrayList<>();
    private List<IdentityInfo> addressLine3 = new ArrayList<>();
    private List<IdentityInfo> location1 = new ArrayList<>();
    private List<IdentityInfo> location2 = new ArrayList<>();
    private List<IdentityInfo> location3 = new ArrayList<>();
    private String postalCode = "";
    private List<IdentityInfo> fullAddress = new ArrayList<>();
    private Map<String, Object> metadata;

    // Getters and Setters
}