package com.phishguard.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * PhishGuard - ConfigLoader.java
 * -------------------------------------------------
 * Singleton that loads and caches all settings from
 * src/main/resources/config.properties at startup.
 *
 * Usage:
 *   ConfigLoader cfg = ConfigLoader.getInstance();
 *   String dbUrl = cfg.get("db.url");
 *   double threshold = cfg.getDouble("risk.threshold.high", 0.85);
 */
public class ConfigLoader {

    // ── Singleton instance ─────────────────────────────────────────────
    private static volatile ConfigLoader instance;

    private final Properties props = new Properties();
    private boolean loaded = false;

    // ── Private constructor (Singleton) ────────────────────────────────
    private ConfigLoader() {
        loadConfig();
    }

    /**
     * Returns the singleton ConfigLoader, creating it on first call.
     * Thread-safe via double-checked locking.
     */
    public static ConfigLoader getInstance() {
        if (instance == null) {
            synchronized (ConfigLoader.class) {
                if (instance == null) {
                    instance = new ConfigLoader();
                }
            }
        }
        return instance;
    }

    // ── Internal loader ────────────────────────────────────────────────

    /**
     * Reads config.properties from the classpath.
     * Throws RuntimeException if the file is missing (application cannot start).
     */
    private void loadConfig() {
        try (InputStream is = getClass().getResourceAsStream(Constants.CONFIG_FILE)) {
            if (is == null) {
                throw new RuntimeException(
                    "[ConfigLoader] FATAL: config.properties not found on classpath! " +
                    "Ensure src/main/resources/config.properties exists."
                );
            }
            props.load(is);
            loaded = true;
            System.out.println("[Config] Loaded " + props.size() + " properties from config.properties");
        } catch (IOException e) {
            throw new RuntimeException("[ConfigLoader] FATAL: Failed to read config.properties", e);
        }
    }

    // ── Public accessors ───────────────────────────────────────────────

    /**
     * Retrieves a String property value by key.
     *
     * @param key the property key
     * @return the value, or null if not found
     */
    public String get(String key) {
        return props.getProperty(key);
    }

    /**
     * Retrieves a String property value with a fallback default.
     *
     * @param key          the property key
     * @param defaultValue returned if the key is absent
     * @return the value or defaultValue
     */
    public String get(String key, String defaultValue) {
        return props.getProperty(key, defaultValue);
    }

    /**
     * Retrieves an integer property value.
     *
     * @param key          the property key
     * @param defaultValue returned if the key is absent or cannot be parsed
     * @return parsed integer or defaultValue
     */
    public int getInt(String key, int defaultValue) {
        String val = props.getProperty(key);
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            System.err.println("[ConfigLoader] Warning: '" + key + "' is not a valid integer. Using default: " + defaultValue);
            return defaultValue;
        }
    }

    /**
     * Retrieves a long property value.
     *
     * @param key          the property key
     * @param defaultValue returned if the key is absent or cannot be parsed
     * @return parsed long or defaultValue
     */
    public long getLong(String key, long defaultValue) {
        String val = props.getProperty(key);
        if (val == null) return defaultValue;
        try {
            return Long.parseLong(val.trim());
        } catch (NumberFormatException e) {
            System.err.println("[ConfigLoader] Warning: '" + key + "' is not a valid long. Using default: " + defaultValue);
            return defaultValue;
        }
    }

    /**
     * Retrieves a double property value.
     *
     * @param key          the property key
     * @param defaultValue returned if the key is absent or cannot be parsed
     * @return parsed double or defaultValue
     */
    public double getDouble(String key, double defaultValue) {
        String val = props.getProperty(key);
        if (val == null) return defaultValue;
        try {
            return Double.parseDouble(val.trim());
        } catch (NumberFormatException e) {
            System.err.println("[ConfigLoader] Warning: '" + key + "' is not a valid double. Using default: " + defaultValue);
            return defaultValue;
        }
    }

    /**
     * Retrieves a boolean property value.
     * Accepts "true"/"false" (case-insensitive).
     *
     * @param key          the property key
     * @param defaultValue returned if the key is absent
     * @return parsed boolean or defaultValue
     */
    public boolean getBoolean(String key, boolean defaultValue) {
        String val = props.getProperty(key);
        if (val == null) return defaultValue;
        return Boolean.parseBoolean(val.trim());
    }

    /**
     * Reloads config.properties from the classpath (and working directory if present).
     * Called by SettingsPanel after saving settings via the GUI.
     */
    public void reload() {
        props.clear();
        loadConfig();
        // Also try to load from working directory (GUI save writes here)
        try {
            java.io.File workingDirConfig = new java.io.File("config.properties");
            if (workingDirConfig.exists()) {
                try (java.io.InputStream fis = new java.io.FileInputStream(workingDirConfig)) {
                    props.load(fis);
                    System.out.println("[Config] Reloaded " + props.size() + " properties (with working-dir override)");
                }
            }
        } catch (Exception e) {
            System.err.println("[Config] Working-dir reload failed: " + e.getMessage());
        }
    }

    /**
     * @return true if config.properties was successfully loaded
     */
    public boolean isLoaded() {
        return loaded;
    }

    /**
     * Prints all loaded configuration keys (masks password values).
     * Useful for startup diagnostics.
     */
    public void printSummary() {
        System.out.println("[Config] ─────────────────────────────────────");
        props.stringPropertyNames().stream().sorted().forEach(key -> {
            String value = key.toLowerCase().contains("password") || key.toLowerCase().contains("key")
                ? "****" : props.getProperty(key);
            System.out.printf("[Config]   %-35s = %s%n", key, value);
        });
        System.out.println("[Config] ─────────────────────────────────────");
    }
}
