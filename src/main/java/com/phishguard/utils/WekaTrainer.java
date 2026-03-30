package com.phishguard.utils;

import weka.classifiers.Evaluation;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SerializationHelper;
import weka.core.converters.ConverterUtils.DataSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * PhishGuard - WekaTrainer.java
 * -------------------------------------------------
 * Standalone training script for Phase 6.
 * Generates synthetic phishing/legitimate URL feature data
 * (or loads real dataset if available), trains RandomForest and NaiveBayes,
 * evaluates them via 10-fold CV, and saves the models to resources.
 */
public class WekaTrainer {

    private static final String DATASET_PATH = "src/main/resources/datasets/phishing_training.arff";
    private static final String RF_MODEL_PATH = "src/main/resources/models/randomforest.model";
    private static final String NB_MODEL_PATH = "src/main/resources/models/naivebayes.model";
    private static final int NUM_SAMPLES = 2000;

    public static void main(String[] args) throws Exception {
        System.out.println("=== PhishGuard Model Trainer ===");
        System.out.println("Initializing training pipeline...");

        // Create output directory
        new File("src/main/resources/models").mkdirs();
        new File("src/main/resources/datasets").mkdirs();

        // Load or generate data
        Instances data = loadOrGenerateData();
        System.out.println("[Trainer] Dataset ready: " + data.numInstances() + " instances");

        // Train models
        trainRandomForest(data);
        trainNaiveBayes(data);

        System.out.println("\n=== Training Complete ===");
        System.out.println("Models saved to: src/main/resources/models/");
        System.out.println("Run Main.java — AIModelEngine will exit fallback mode");
    }

    private static Instances loadOrGenerateData() {
        try {
            File file = new File(DATASET_PATH);
            if (file.exists()) {
                System.out.println("[Trainer] Loading real dataset from " + DATASET_PATH);
                Instances data = DataSource.read(DATASET_PATH);
                data.setClassIndex(data.numAttributes() - 1);
                return data;
            }
        } catch (Exception e) {
            System.out.println("[Trainer] Could not load dataset: " + e.getMessage());
        }

        System.out.println("[Trainer] Generating " + NUM_SAMPLES + " synthetic URL samples...");
        return generateSyntheticData();
    }

    private static Instances generateSyntheticData() {
        // Use exactly the dataset header expected by AIModelEngine
        ArrayList<Attribute> attributes = new ArrayList<>();
        attributes.add(new Attribute("url_length"));
        attributes.add(new Attribute("has_https"));
        attributes.add(new Attribute("has_ip_address"));
        attributes.add(new Attribute("suspicious_keyword_count"));
        attributes.add(new Attribute("dot_count"));
        attributes.add(new Attribute("special_char_count"));
        attributes.add(new Attribute("entropy"));
        attributes.add(new Attribute("subdomain_count"));

        List<String> classValues = Arrays.asList("legitimate", "phishing");
        attributes.add(new Attribute("class", classValues));

        Instances dataset = new Instances("PhishingURLs", attributes, NUM_SAMPLES);
        dataset.setClassIndex(8);

        Random rand = new Random(42);

        // Generate PHISHING samples (1000)
        for (int i = 0; i < NUM_SAMPLES / 2; i++) {
            double[] features = new double[9];
            if (rand.nextDouble() > 0.1) {
                // Typical phishing profile
                features[0] = 0.5 + rand.nextDouble() * 0.5; // long URLs
                features[1] = 0.0; // no HTTPS
                features[2] = rand.nextBoolean() ? 1.0 : 0.0; // sometimes IP
                features[3] = 0.3 + rand.nextDouble() * 0.5; // many keywords
                features[4] = 0.3 + rand.nextDouble() * 0.4; // many dots
                features[5] = 0.3 + rand.nextDouble() * 0.5; // many special chars
                features[6] = 3.8 + rand.nextDouble() * 1.2; // high entropy
                features[7] = 0.2 + rand.nextDouble() * 0.6; // many subdomains
            } else {
                // Noise (10%)
                for (int j = 0; j < 8; j++) features[j] = rand.nextDouble();
            }
            Instance inst = new DenseInstance(1.0, features);
            inst.setDataset(dataset);
            inst.setClassValue("phishing");
            dataset.add(inst);
        }

        // Generate LEGITIMATE samples (1000)
        for (int i = 0; i < NUM_SAMPLES / 2; i++) {
            double[] features = new double[9];
            if (rand.nextDouble() > 0.1) {
                // Typical legitimate profile
                features[0] = 0.05 + rand.nextDouble() * 0.30; // short URLs
                features[1] = 1.0; // HTTPS
                features[2] = 0.0; // no IP
                features[3] = rand.nextDouble() * 0.15; // few keywords
                features[4] = 0.1 + rand.nextDouble() * 0.2; // few dots
                features[5] = rand.nextDouble() * 0.2; // few special chars
                features[6] = 2.5 + rand.nextDouble() * 1.3; // normal entropy
                features[7] = rand.nextDouble() * 0.2; // few subdomains
            } else {
                // Noise (10%)
                for (int j = 0; j < 8; j++) features[j] = rand.nextDouble();
            }
            Instance inst = new DenseInstance(1.0, features);
            inst.setDataset(dataset);
            inst.setClassValue("legitimate");
            dataset.add(inst);
        }

        return dataset;
    }

    private static void trainRandomForest(Instances dataset) throws Exception {
        System.out.println("[Trainer] Training Random Forest (100 trees)...");
        RandomForest rf = new RandomForest();
        rf.setNumIterations(100);
        rf.setNumFeatures(3);
        rf.setMaxDepth(0);
        rf.buildClassifier(dataset);

        SerializationHelper.write(RF_MODEL_PATH, rf);
        System.out.println("[Trainer] Random Forest saved ✓");
        System.out.println("[Trainer] RF built with " + dataset.numInstances() + " instances");

        Evaluation eval = new Evaluation(dataset);
        eval.crossValidateModel(rf, dataset, 10, new Random(42));
        System.out.println("[Trainer] RF 10-fold CV Accuracy: " + String.format("%.2f%%", eval.pctCorrect()));
        System.out.println("[Trainer] RF False Positive Rate: " + String.format("%.4f", eval.falsePositiveRate(1))); // class index 1 is "phishing" or depends on the order. wait, class index 0 is legitimate. So FPR for class 1 (phishing) means legit classified as phishing. Yes.
    }

    private static void trainNaiveBayes(Instances dataset) throws Exception {
        System.out.println("[Trainer] Training Naive Bayes...");
        NaiveBayes nb = new NaiveBayes();
        nb.buildClassifier(dataset);

        SerializationHelper.write(NB_MODEL_PATH, nb);
        System.out.println("[Trainer] Naive Bayes saved ✓");

        Evaluation eval = new Evaluation(dataset);
        eval.crossValidateModel(nb, dataset, 10, new Random(42));
        System.out.println("[Trainer] NB 10-fold CV Accuracy: " + String.format("%.2f%%", eval.pctCorrect()));
    }
}
