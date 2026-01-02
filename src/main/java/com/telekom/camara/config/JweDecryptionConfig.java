package com.telekom.camara.config;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * Configuration for JWE (JSON Web Encryption) decryption.
 */
@Configuration
@Slf4j
public class JweDecryptionConfig {

    @Value("${jwe.decryption.private-key-path}")
    private Resource privateKeyResource;

    @Value("${jwe.decryption.key-algorithm}")
    private String keyAlgorithm;

    @Bean
    public JWEDecrypter jweDecrypter() {
        try {
            log.info("Loading JWE decryption private key from: {}", privateKeyResource.getDescription());
            
            RSAPrivateKey privateKey = loadPrivateKey();
            
            // Verify the key algorithm is supported
            JWEAlgorithm algorithm = JWEAlgorithm.parse(keyAlgorithm);
            if (!algorithm.equals(JWEAlgorithm.RSA_OAEP_256) && 
                !algorithm.equals(JWEAlgorithm.RSA_OAEP) &&
                !algorithm.equals(JWEAlgorithm.RSA1_5)) {
                throw new IllegalArgumentException("Unsupported JWE key algorithm: " + keyAlgorithm);
            }
            
            RSADecrypter decrypter = new RSADecrypter(privateKey);
            log.info("JWE decrypter initialized successfully with algorithm: {}", keyAlgorithm);
            
            return decrypter;
            
        } catch (Exception e) {
            log.error("Failed to initialize JWE decrypter", e);
            throw new IllegalStateException("Could not load JWE decryption key", e);
        }
    }

    private RSAPrivateKey loadPrivateKey() throws Exception {
        try (PEMParser pemParser = new PEMParser(
                new InputStreamReader(privateKeyResource.getInputStream(), StandardCharsets.UTF_8))) {
            
            Object object = pemParser.readObject();
            PrivateKeyInfo privateKeyInfo;
            
            if (object instanceof PrivateKeyInfo) {
                privateKeyInfo = (PrivateKeyInfo) object;
            } else if (object instanceof PEMKeyPair) {
                privateKeyInfo = ((PEMKeyPair) object).getPrivateKeyInfo();
            } else {
                throw new IllegalArgumentException(
                    "Expected PrivateKeyInfo but got: " + object.getClass().getName());
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);

            if (!(privateKey instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException("Private key is not an RSA key");
            }

            return (RSAPrivateKey) privateKey;
        }
    }
}
