package com.telekom.camara.integration;

public class MockAuthServerRunner {
    public static void main(String[] args) {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8090;

        MockAuthorizationServer server = new MockAuthorizationServer();
        server.start(port);

        System.out.println("\n" + "=".repeat(60));
        System.out.println("Mock Authorization Server started successfully!");
        System.out.println("=".repeat(60));
        System.out.println("Port:     " + server.getPort());
        System.out.println("JWKS URL: " + server.getJwksUrl());
        System.out.println("\nExample token generation:");
        System.out.println("  String token = server.generateValidToken(\"+1234567890\");");
        System.out.println("\nGenerated sample token:");
        String sampleToken = server.generateValidToken("+1234567890");
        System.out.println("  " + sampleToken);
        System.out.println("\nTest with curl:");
        System.out.println("  curl -X POST http://localhost:8080/number-verification/v0/verify \\");
        System.out.println("    -H \"Authorization: Bearer " + sampleToken + "\" \\");
        System.out.println("    -H \"Content-Type: application/json\" \\");
        System.out.println("    -d '{\"phoneNumber\":\"+1234567890\"}'");
        System.out.println("\nPress Ctrl+C to stop the server...");
        System.out.println("=".repeat(60) + "\n");

        // Keep the server running
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nShutting down Mock Authorization Server...");
            server.shutdown();
            System.out.println("Server stopped.");
        }));

        // Keep the main thread alive
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}