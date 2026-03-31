package com.phishguard.gui;

import javax.swing.JComponent;
import javax.swing.Timer;
import java.util.function.Consumer;

public class Animator {
    
    // Count up animation for stat cards
    public static void countUp(int from, int to, int durationMs,
                               Consumer<Integer> onUpdate) {
        if (durationMs <= 0) { onUpdate.accept(to); return; }
        int[] current = {from};
        Timer t = new Timer(30, null);
        t.addActionListener(e -> {
            int diff = to - current[0];
            int stepVal = Math.max(1, Math.abs(diff) / 10);
            
            if (current[0] < to) {
                current[0] += stepVal;
                if (current[0] >= to) { current[0] = to; t.stop(); }
            } else if (current[0] > to) {
                current[0] -= stepVal;
                if (current[0] <= to) { current[0] = to; t.stop(); }
            } else {
                t.stop();
            }
            onUpdate.accept(current[0]);
        });
        t.start();
    }
    
    // Fade in component
    public static void fadeIn(JComponent comp, int durationMs) {
        // Simply make visible with a short delay — no alpha needed
        comp.setVisible(false);
        Timer t = new Timer(durationMs / 10, null);
        int[] step = {0};
        t.addActionListener(e -> {
            step[0]++;
            if (step[0] == 1) comp.setVisible(true);
            if (step[0] >= 10) ((Timer)e.getSource()).stop();
        });
        t.start();
    }
    
    // Slide up animation
    public static void slideUp(JComponent comp, int startY, 
                               int endY, int durationMs) {
        int[] y = {startY};
        Timer t = new Timer(16, null);
        t.addActionListener(e -> {
            y[0] += (endY - y[0]) / 5;
            if (Math.abs(y[0] - endY) < 2) { y[0] = endY; t.stop(); }
            comp.setLocation(comp.getX(), y[0]);
        });
        t.start();
    }
}
