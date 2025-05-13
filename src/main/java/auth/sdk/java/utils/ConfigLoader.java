package auth.sdk.java.utils;

import com.moandjiezana.toml.Toml;

import java.io.File;

public class ConfigLoader {
    private static final String CONFIG_FILE_PATH = "./src/main/resources/config.toml";

    public Config loadConfig() {
        File configFile = new File(CONFIG_FILE_PATH);
        if (!configFile.exists()) {
            throw new IllegalArgumentException("Configuration file not found at: " + CONFIG_FILE_PATH);
        }
        new Toml().read(configFile);
        Config config = new Toml().read(configFile).to(Config.class);
        if (config.getMosip_auth_server() == null) {
            throw new IllegalArgumentException("Missing [mosip_auth_server] section in the configuration file.");
        }
        return config;
    }
}