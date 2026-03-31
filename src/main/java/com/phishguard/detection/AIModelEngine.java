package com.phishguard.detection;

import com.phishguard.utils.Constants;
import weka.classifiers.Classifier;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.trees.RandomForest;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SerializationHelper;

import java.io.InputStream;

/**
 * AIModelEngine — loads Weka RandomForest + NaiveBayes models,
 * predicts phishing probability for a given URL feature vector.
 *
 * Thread-safety: a fresh Instances clone is created per prediction call.
 * Model references are read-only after loadModels() completes.
 */
public final class AIModelEngine {

    // ── Model instances (loaded once, read-only after init) ──────────────
    private static Classifier rfModel;
    private static Classifier nbModel;

    // ── Dataset header (schema only — NO data rows, cloned per prediction) ─
    private static Instances datasetHeader;

    private static boolean loaded      = false;
    private static boolean fallbackMode = true;

    private AIModelEngine() {}

    // ── Load ──────────────────────────────────────────────────────────────

    /**
     * Attempts to load both Weka models from classpath resources.
     * Sets fallbackMode = false only if BOTH models load successfully.
     */
    public static synchronized void loadModels() {
        if (loaded && !fallbackMode) {
            System.out.println("[AIModel] Models already loaded.");
            return;
        }

        System.out.println("[AIModel] Attempting to load Weka models...");

        boolean rfLoaded = false, nbLoaded = false;

        // ── Load Random Forest model ────────────────────────────────────
        try (InputStream rfStream = AIModelEngine.class.getResourceAsStream(Constants.MODEL_PATH_RF)) {
            if (rfStream == null) {
                System.out.println("[AIModel] randomforest.model not found on classpath.");
            } else {
                rfModel = (Classifier) SerializationHelper.read(rfStream);
                // FIX 1: deterministic tie-breaking if it's a RandomForest
                if (rfModel instanceof RandomForest) {
                    ((RandomForest) rfModel).setSeed(42);
                }
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
                nbModel = (Classifier) SerializationHelper.read(nbStream);
                nbLoaded = true;
                System.out.println("[AIModel] Naive Bayes model loaded successfully.");
            }
        } catch (Exception e) {
            System.err.println("[AIModel] Error loading Naive Bayes model: " + e.getMessage());
        }

        // ── Build schema ────────────────────────────────────────────────
        datasetHeader = buildDatasetHeader();

        if (rfLoaded && nbLoaded) {
            fallbackMode = false;
            loaded       = true;
            System.out.println("[AIModel] ✓ REAL MODEL MODE — fallback disabled");
        } else {
            fallbackMode = true;
            loaded       = true;
            System.out.println("[AIModel] *** Running in FALLBACK MODE — models not found ***");
        }
    }

    // ── Prediction ──────────────────────────────────────────────────────

    /**
     * Convenient wrapper that extracts features and predicts probability.
     */
    public static double predict(String url) throws Exception {
        if (url == null || url.isBlank()) return 0.0;
        double[] features = URLFeatureExtractor.extract(url);
        return predict(features);
    }

    /**
     * Thread-safe prediction logic using an isolated Instances container.
     */
    public static double predict(double[] features) throws Exception {
        if (fallbackMode || !loaded || rfModel == null || nbModel == null) {
            return fallbackHeuristic(features);
        }

        // FIX 2: Create an isolated Instances container per prediction.
        //         Never share a mutable Instances object across threads.
        Instances localHeader = new Instances(datasetHeader, 0); 

        // Build the instance
        Instance inst = new DenseInstance(Constants.FEATURE_COUNT + 1);
        inst.setDataset(localHeader);
        for (int i = 0; i < Constants.FEATURE_COUNT; i++) {
            inst.setValue(i, features[i]);
        }
        inst.setClassMissing();
        localHeader.add(inst);

        // Get probability distributions (index 1 = phishing class)
        Instance testInstance = localHeader.instance(0);
        double[] rfDist = rfModel.distributionForInstance(testInstance);
        double[] nbDist = nbModel.distributionForInstance(testInstance);

        double rfScore = (rfDist.length > 1) ? rfDist[1] : rfDist[0];
        double nbScore = (nbDist.length > 1) ? nbDist[1] : nbDist[0];

        // Weighted ensemble
        double ensemble = (rfScore * Constants.ENSEMBLE_WEIGHT_RF)
                        + (nbScore * Constants.ENSEMBLE_WEIGHT_NB);

        System.out.printf("[AIModel] RF=%.3f  NB=%.3f  Ensemble=%.3f%n", 
                          rfScore, nbScore, ensemble);

        return Math.min(1.0, Math.max(0.0, ensemble));
    }

    // ── Fallback Heuristic ────────────────────────────────────────────────

    private static double fallbackHeuristic(double[] features) {
        double score = 0.0;
        score += (features[Constants.FEAT_HAS_HTTPS] == 0.0) ? 0.30 : 0.0;
        score += features[Constants.FEAT_HAS_IP] * 0.40;
        score += features[Constants.FEAT_KEYWORD_COUNT] * 0.15;
        score += (features[Constants.FEAT_ENTROPY] > Constants.HIGH_ENTROPY_THRESHOLD)
                 ? 0.20
                 : (features[Constants.FEAT_ENTROPY] / 5.0) * 0.20;
        return Math.min(1.0, score);
    }

    // ── Dataset Header Builder ────────────────────────────────────────────

    /**
     * Builds the Weka Instances header matching the 8 features.
     * Aligned with URLFeatureExtractor indices.
     */
    private static Instances buildDatasetHeader() {
        java.util.ArrayList<weka.core.Attribute> attrs = new java.util.ArrayList<>();

        // Must match FEATURE_COUNT indices exactly!
        attrs.add(new weka.core.Attribute("url_length"));         // 0
        attrs.add(new weka.core.Attribute("has_https"));          // 1
        attrs.add(new weka.core.Attribute("has_ip_address"));     // 2
        attrs.add(new weka.core.Attribute("keyword_count"));      // 3
        attrs.add(new weka.core.Attribute("dot_count"));          // 4
        attrs.add(new weka.core.Attribute("special_char_count")); // 5
        attrs.add(new weka.core.Attribute("entropy"));            // 6
        attrs.add(new weka.core.Attribute("subdomain_count"));    // 7

        // Class attribute
        java.util.ArrayList<String> classVals = new java.util.ArrayList<>();
        classVals.add("legitimate");
        classVals.add("phishing");
        attrs.add(new weka.core.Attribute("class", classVals));

        Instances header = new Instances("PhishGuardURLs", attrs, 0);
        header.setClassIndex(Constants.FEATURE_COUNT); 
        return header;
    }

    public static boolean isLoaded()       { return loaded; }
    public static boolean isFallbackMode() { return fallbackMode; }
}
