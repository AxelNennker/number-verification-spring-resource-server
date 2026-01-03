package com.telekom.camara.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class JweDecryptionConfig {

    private static final Logger logger = LoggerFactory.getLogger(JweDecryptionConfig.class);

    @Value("${camara.jwe.decryption.private-key-path:/opt/CAMARA/resourceservers/numberverification/private-key.pem}")
    private String privateKeyPath;

    /**
     * Creates RSADecrypter bean only when the private key path is configured.
     * In tests, this bean will be overridden by @Primary bean from TestJweDecryptionConfig.
     */
    @Bean
    public RSADecrypter jweDecrypter() throws IOException, JOSEException {
        if (privateKeyPath == null) {
            throw new IllegalStateException("JWE private key file not configured");
        }
        File file = new File(privateKeyPath);
        if (!file.exists()) {
            throw new IllegalStateException("JWE private key file not found");
        }
        try (FileInputStream fis = new FileInputStream(file)) {
            logger.info("Loading JWE decryption private key from: {}", file.getAbsolutePath());

            String pemContent = new String(fis.readAllBytes(), StandardCharsets.UTF_8);
            RSAPrivateKey privateKey = loadPrivateKeyFromPEM(pemContent);

            logger.info("JWE decrypter initialized successfully with algorithm: {}}", privateKey.getAlgorithm());
            return new RSADecrypter(privateKey);
        }
    }

//    private RSAPrivateKey loadPrivateKeyFromPEM(String pemContent) throws IOException {
//        try {
//            String privateKeyPEM = pemContent
//                    .replace("-----BEGIN PRIVATE KEY-----", "")
//                    .replace("-----END PRIVATE KEY-----", "")
//                    .replaceAll("\\s", "");
//
//            byte[] encoded = java.util.Base64.getDecoder().decode(privateKeyPEM);
//            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
//            java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(encoded);
//            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
//        } catch (Exception e) {
//            throw new IOException("Failed to load private key from PEM", e);
//        }
//    }

    private RSAPrivateKey loadPrivateKeyFromPEM(String pemContent) {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemContent))) {
            Object object = pemParser.readObject();

            PrivateKeyInfo privateKeyInfo;
            if (object instanceof PrivateKeyInfo) {
                privateKeyInfo = (PrivateKeyInfo) object;
            } else if (object instanceof PEMKeyPair) {
                PEMKeyPair pemKeyPair = (PEMKeyPair) object;
                privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
            } else {
                throw new IllegalArgumentException(
                        "Expected PrivateKeyInfo or PEMKeyPair but got: " + object.getClass().getName());
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);

            if (!(privateKey instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException("Private key is not an RSA key");
            }

            return (RSAPrivateKey) privateKey;

        } catch (IOException e) {
            throw new RuntimeException("Failed to load private key from PEM", e);
        }
    }

}