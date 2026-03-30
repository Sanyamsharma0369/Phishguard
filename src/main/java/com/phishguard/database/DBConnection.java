package com.phishguard.database;

import com.phishguard.utils.ConfigLoader;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * PhishGuard - DBConnection.java
 * -------------------------------------------------
 * Singleton JDBC connection to MySQL 8.0.
 *
 * Usage:
 *   Connection conn = DBConnection.getInstance().getConnection();
 *
 * The connection is lazily initialized on the first call to getConnection().
 * If the connection drops, getConnection() will automatically reconnect.
 *
 * Thread safety: The singleton itself is thread-safe (double-checked locking).
 * For multi-threaded use of the connection, callers must synchronize externally
 * or use a connection pool (future enhancement).
 */
public class DBConnection {

    // ── Singleton instance ─────────────────────────────────────────────
    private static volatile DBConnection instance;

    private Connection connection;

    // ── Private constructor ────────────────────────────────────────────
    private DBConnection() {
        // Connection is established lazily in getConnection()
    }

    /**
     * Returns the singleton DBConnection manager.
     * Thread-safe via double-checked locking.
     */
    public static DBConnection getInstance() {
        if (instance == null) {
            synchronized (DBConnection.class) {
                if (instance == null) {
                    instance = new DBConnection();
                }
            }
        }
        return instance;
    }

    // ── Connection management ──────────────────────────────────────────

    /**
     * Returns a live JDBC Connection to the phishguard database.
     * Connects on first call; reconnects automatically if the connection is lost.
     *
     * @return active JDBC Connection
     * @throws RuntimeException if unable to establish a connection
     */
    public Connection getConnection() {
        try {
            // Reconnect if closed or null
            if (connection == null || connection.isClosed()) {
                connect();
            }
        } catch (SQLException e) {
            System.err.println("[DB] Connection check failed, attempting reconnect...");
            connect();
        }
        return connection;
    }

    /**
     * Performs the actual JDBC connection using settings from ConfigLoader.
     * Prints a confirmation message on success.
     *
     * @throws RuntimeException if the JDBC connection cannot be established
     */
    private void connect() {
        ConfigLoader cfg = ConfigLoader.getInstance();

        String url      = cfg.get("db.url",      "jdbc:mysql://localhost:3306/phishguard");
        String user     = cfg.get("db.user",     "root");
        String password = cfg.get("db.password", "");

        try {
            // Explicitly load the MySQL JDBC driver (required in some environments)
            Class.forName("com.mysql.cj.jdbc.Driver");

            connection = DriverManager.getConnection(url, user, password);
            connection.setAutoCommit(true);

            System.out.println("[DB] Connected to MySQL: " + url.split("\\?")[0]);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(
                "[DB] FATAL: MySQL JDBC driver not found. " +
                "Ensure mysql-connector-j is in your classpath.", e
            );
        } catch (SQLException e) {
            throw new RuntimeException(
                "[DB] FATAL: Cannot connect to database at '" + url + "'\n" +
                "   → Check your db.url, db.user, db.password in config.properties\n" +
                "   → Ensure MySQL is running and the 'phishguard' database exists (run schema.sql)\n" +
                "   → SQL Error: " + e.getMessage(), e
            );
        }
    }

    /**
     * Closes the active JDBC connection.
     * Should be called on application shutdown.
     */
    public void close() {
        if (connection != null) {
            try {
                connection.close();
                System.out.println("[DB] Connection closed gracefully.");
            } catch (SQLException e) {
                System.err.println("[DB] Warning: Error while closing connection: " + e.getMessage());
            } finally {
                connection = null;
            }
        }
    }

    /**
     * @return true if the connection is currently open and valid
     */
    public boolean isConnected() {
        try {
            return connection != null && !connection.isClosed() && connection.isValid(2);
        } catch (SQLException e) {
            return false;
        }
    }
}
