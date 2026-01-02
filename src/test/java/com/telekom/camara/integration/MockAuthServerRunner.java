package com.telekom.camara.integration;

public class MockAuthServerRunner {
    public static void main(String[] args) {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8090;

        MockAuthorizationServer server = new MockAuthorizationServer();
        server.start(port);

        System.out.println("\n" + "=".repeat(80));
        System.out.println("Mock Authorization Server started successfully!");
        System.out.println("=".repeat(80));
        System.out.println("Port:                " + server.getPort());
        System.out.println("JWKS URL:            " + server.getJwksUrl());
        System.out.println("OpenID Config:       http://localhost:" + server.getPort() + "/.well-known/openid-configuration");
        System.out.println();
        System.out.println("Public Encryption Key (for resource server configuration):");
        System.out.println(server.getPublicEncryptionKey().toJSONString());
        System.out.println();
        System.out.println("Example token generation:");
        System.out.println("  String token = server.generateValidToken(");
        System.out.println("      \"+1234567890\",");
        System.out.println("      \"number-verification:verify\",");
        System.out.println("      \"/number-verification/v0/verify\"");
        System.out.println("  );");
        System.out.println();
        System.out.println("Generated sample verify token:");
        String verifyToken = server.generateValidToken(
                "+1234567890",
                "number-verification:verify",
                "/number-verification/v0/verify"
        );
        System.out.println("  " + verifyToken);
        System.out.println();
        System.out.println("Generated sample device-phone-number token:");
        String readToken = server.generateValidToken(
                "+1234567890",
                "number-verification:device-phone-number:read",
                "/number-verification/v0/device-phone-number"
        );
        System.out.println("  " + readToken);
        System.out.println();
        System.out.println("Test verify endpoint with curl:");
        System.out.println("  curl -X POST http://localhost:8080/number-verification/v0/verify \\");
        System.out.println("    -H \"Authorization: Bearer " + verifyToken + "\" \\");
        System.out.println("    -H \"Content-Type: application/json\" \\");
        System.out.println("    -d '{\"phoneNumber\":\"+1234567890\"}'");
        System.out.println();
        System.out.println("Test device-phone-number endpoint with curl:");
        System.out.println("  curl -X POST http://localhost:8080/number-verification/v0/device-phone-number \\");
        System.out.println("    -H \"Authorization: Bearer " + readToken + "\" \\");
        System.out.println("    -H \"Content-Type: application/json\" \\");
        System.out.println("    -d '{}'");
        System.out.println();
        System.out.println("Press Ctrl+C to stop the server...");
        System.out.println("=".repeat(80) + "\n");

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