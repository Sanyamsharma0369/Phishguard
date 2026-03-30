package com.phishguard.detection;

import com.phishguard.utils.Constants;
import weka.classifiers.Classifier;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SerializationHelper;

import java.io.InputStream;
import java.util.ArrayList;

/**
 * PhishGuard - AIModelEngine.java
 * -------------------------------------------------
 * Loads pre-trained Weka ML models (XGBoost + RandomForest ensemble)
 * and predicts phishing probability for a given URL.
 *
 * MODEL FILES (placed in src/main/resources/models/ after training):
 *   - models/xgboost.model      → Weka XGBoost tree ensemble
 *   - models/randomforest.model → Weka RandomForest classifier
 *
 * ENSEMBLE STRATEGY:
 *   finalScore = (rfScore + xgScore) / 2.0
 *
 * FALLBACK MODE (when model files are missing):
 *   Uses a hand-crafted heuristic formula derived from URL features:
 *   score = noHttps(0.30) + hasIp(0.40) + keywords(0.15) + entropy(0.20)
 *   This ensures the system works end-to-end before models are trained.
 *
 * USAGE:
 *   AIModelEngine.loadModels();           // call once at startup
 *   double score = AIModelEngine.predict(url);  // call per URL
 */
public final class AIModelEngine {

    // ── Model state ─────────────────────────────────────────────────────
    private static Classifier randomForestModel = null;
    private static Classifier naiveBayesModel     = null;
    private static boolean    fallbackMode       = true;

    // ── Weka dataset structure (shared Instances header) ─────────────────
    private static Instances datasetHeader = null;

    private AIModelEngine() {}

    // ── Startup ─────────────────────────────────────────────────────────

    /**
     * Attempts to load both Weka models from classpath resources/models/.
     * Sets fallbackMode = false only if BOTH models load successfully.
     * Safe to call multiple times (subsequent calls are no-ops).
     *
     * Should be called from Main.java during application startup.
     */
    public static void loadModels() {
        if (!fallbackMode) {
            System.out.println("[AIModel] Models already loaded.");
            return;
        }

        System.out.println("[AIModel] Attempting to load Weka models...");

        // Build the shared Weka Instances header (schema for instances)
        datasetHeader = buildDatasetHeader();

        boolean rfLoaded = false, nbLoaded = false;

        // ── Load Random Forest model ────────────────────────────────────
        try (InputStream rfStream = AIModelEngine.class.getResourceAsStream(Constants.MODEL_PATH_RF)) {
            if (rfStream == null) {
                System.out.println("[AIModel] randomforest.model not found on classpath.");
            } else {
                randomForestModel = (Classifier) SerializationHelper.read(rfStream);
                rfLoaded = true;
                System.out.println("[AIModel] RandomForest model loaded successfully.");
            }
        } catch (Exception e) {
            System.err.println("[AIModel] Error loading RandomForest model: " + e.getMessage());
        }

        // ── Load Naive Bayes model ──────────────────────────────────────
        try (InputStream nbStream = AIModelEngine.class.getResourceAsStream(Constants.MODEL_PATH_NB)) {
            if (nbStream == null) {
                System.out.println("[AIModel] naivebayes.model not found on classpath.");
            } else {
                naiveBayesModel = (Classifier) SerializationHelper.read(nbStream);
                nbLoaded = true;
                System.out.println("[AIModel] Naive Bayes model loaded successfully.");
            }
        } catch (Exception e) {
            System.err.println("[AIModel] Error loading Naive Bayes model: " + e.getMessage());
        }

        // ── Determine mode ──────────────────────────────────────────────
        if (rfLoaded && nbLoaded) {
            fallbackMode = false;
            System.out.println("[AIModel] ✓ REAL MODEL MODE — fallback disabled");
        } else {
            fallbackMode = true;
            System.out.println("[AIModel] *** Running in FALLBACK MODE — models not found ***");
            System.out.println("[AIModel]     Train models and place in src/main/resources/models/ to enable ML scoring.");
        }
    }

    // ── Prediction ──────────────────────────────────────────────────────

    /**
     * Predicts phishing probability for the given URL.
     *
     * @param url the URL to analyze
     * @return phishing probability: 0.0 (safe) to 1.0 (phishing)
     * @throws Exception if model prediction fails unexpectedly
     */
    public static double predict(String url) throws Exception {
        if (url == null || url.isBlank()) {
            return 0.0;
        }

        // Extract 8-feature vector
        double[] features = URLFeatureExtractor.extract(url);

        if (fallbackMode) {
            return fallbackPredict(features);
        }

        return ensemblePredict(features);
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /**
     * Ensemble prediction: average of RandomForest and XGBoost scores.
     * Both classifiers must be loaded (fallbackMode == false).
     *
     * Weka classifiers return a distribution array: [prob_legitimate, prob_phishing]
     * We return the "phishing" class probability (index 1).
     *
     * @param features 8-element normalized feature array from URLFeatureExtractor
     * @return ensemble phishing probability
     * @throws Exception on Weka classification failure
     */
    private static double ensemblePredict(double[] features) throws Exception {
        // Build a Weka DenseInstance from the feature array
        Instance instance = buildInstance(features);

        // Get class probability distributions
        double[] rfDist = randomForestModel.distributionForInstance(instance);
        double[] nbDist = naiveBayesModel.distributionForInstance(instance);

        // Index 1 = "phishing" class probability
        double rfScore = (rfDist.length > 1) ? rfDist[1] : rfDist[0];
        double nbScore = (nbDist.length > 1) ? nbDist[1] : nbDist[0];

        double ensembleScore = (rfScore * 0.65) + (nbScore * 0.35);
        System.out.printf("[AIModel] RF=%.3f  NB=%.3f  Ensemble=%.3f%n", rfScore, nbScore, ensembleScore);

        return clamp(ensembleScore);
    }

    /**
     * Fallback heuristic scoring when model files are absent.
     * Derived from URL features with manually tuned weights.
     *
     * Formula:
     *   score = noHttps   × 0.30   (missing HTTPS is a strong signal)
     *         + hasIp     × 0.40   (IP-based URLs are almost always phishing)
     *         + keywords  × 0.15   (normalized keyword count)
     *         + entropy   × 0.20   (if entropy > 3.5, else 0)
     *
     * @param features feature array from URLFeatureExtractor
     * @return heuristic phishing score [0.0, 1.0]
     */
    private static double fallbackPredict(double[] features) {
        double score = 0.0;

        // No HTTPS (features[1] == 0 means no HTTPS → 0.30 penalty)
        score += (features[Constants.FEAT_HAS_HTTPS] == 0.0) ? 0.30 : 0.0;

        // Has IP address (strong phishing indicator)
        score += features[Constants.FEAT_HAS_IP] * 0.40;

        // Suspicious keyword density
        score += features[Constants.FEAT_KEYWORD_COUNT] * 0.15;

        // High entropy (> threshold → 0.20 penalty; raw entropy ÷ 5.0 otherwise)
        score += (features[Constants.FEAT_ENTROPY] > Constants.HIGH_ENTROPY_THRESHOLD)
                 ? 0.20
                 : (features[Constants.FEAT_ENTROPY] / 5.0) * 0.20;

        return clamp(score);
    }

    /**
     * Builds a Weka DenseInstance using the shared dataset header.
     * The class attribute (index 8) is set to missing as we are predicting it.
     *
     * @param features 8-element double array
     * @return Weka Instance ready for classification
     */
    private static Instance buildInstance(double[] features) {
        // Create instance with 9 slots: 8 features + 1 class attribute
        Instance instance = new DenseInstance(Constants.FEATURE_COUNT + 1);
        instance.setDataset(datasetHeader);

        for (int i = 0; i < Constants.FEATURE_COUNT; i++) {
            instance.setValue(i, features[i]);
        }

        // Class attribute is missing (to predict)
        instance.setClassMissing();

        return instance;
    }

    /**
     * Builds the Weka Instances header (schema) that matches the 8 features.
     * All 8 features are NUMERIC. Class is NOMINAL: {"legitimate","phishing"}.
     * This header must match the schema used during model training.
     *
     * @return Weka Instances structure with 0 data rows
     */
    private static Instances buildDatasetHeader() {
        ArrayList<Attribute> attrs = new ArrayList<>();

        // 8 numeric feature attributes (same names used during training)
        attrs.add(new Attribute("url_length"));
        attrs.add(new Attribute("has_https"));
        attrs.add(new Attribute("has_ip_address"));
        attrs.add(new Attribute("suspicious_keyword_count"));
        attrs.add(new Attribute("dot_count"));
        attrs.add(new Attribute("special_char_count"));
        attrs.add(new Attribute("entropy"));
        attrs.add(new Attribute("subdomain_count"));

        // Nominal class attribute
        ArrayList<String> classValues = new ArrayList<>();
        classValues.add("legitimate");
        classValues.add("phishing");
        attrs.add(new Attribute("class", classValues));

        Instances header = new Instances("PhishGuardURLs", attrs, 0);
        header.setClassIndex(Constants.FEATURE_COUNT); // class is the 9th attribute (index 8)

        return header;
    }

    /**
     * Clamps a score to the range [0.0, 1.0].
     */
    private static double clamp(double score) {
        return Math.max(0.0, Math.min(1.0, score));
    }

    // ── Public getters ──────────────────────────────────────────────────

    /**
     * @return true if running without trained model files (heuristic mode)
     */
    public static boolean isFallbackMode() {
        return fallbackMode;
    }

    /**
     * @return the shared Weka Instances header (useful for training scripts)
     */
    public static Instances getDatasetHeader() {
        if (datasetHeader == null) {
            datasetHeader = buildDatasetHeader();
        }
        return datasetHeader;
    }
}
