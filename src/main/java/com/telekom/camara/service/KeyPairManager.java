package com.telekom.camara.service;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Service
@Slf4j
public class KeyPairManager {

    private static final int KEY_SIZE = 2048;
    private static final String ALGORITHM = "RSA";

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(KEY_SIZE, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();
            log.info("Generated new RSA key pair with size: {} bits", KEY_SIZE);
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate key pair", e);
        }
    }

    public String privateKeyToPem(PrivateKey privateKey) {
        try (StringWriter stringWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(privateKey);
            pemWriter.flush();
            return stringWriter.toString();
        } catch (IOException e) {
            throw new RuntimeException("Failed to convert private key to PEM", e);
        }
    }

    public String publicKeyToPem(PublicKey publicKey) {
        try (StringWriter stringWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(publicKey);
            pemWriter.flush();
            return stringWriter.toString();
        } catch (IOException e) {
            throw new RuntimeException("Failed to convert public key to PEM", e);
        }
    }

    public RSAPrivateKey loadPrivateKeyFromPem(String pemContent) {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemContent))) {
            Object object = pemParser.readObject();
            
            if (object instanceof PrivateKeyInfo) {
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
                
                if (!(privateKey instanceof RSAPrivateKey)) {
                    throw new IllegalArgumentException("Private key is not an RSA key");
                }
                
                return (RSAPrivateKey) privateKey;
            } else {
                throw new IllegalArgumentException(
                    "Expected PrivateKeyInfo but got: " + object.getClass().getName());
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load private key from PEM", e);
        }
    }

    public RSAPublicKey loadPublicKeyFromPem(String pemContent) {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemContent))) {
            Object object = pemParser.readObject();
            
            if (object instanceof SubjectPublicKeyInfo) {
                SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) object;
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                PublicKey publicKey = converter.getPublicKey(publicKeyInfo);
                
                if (!(publicKey instanceof RSAPublicKey)) {
                    throw new IllegalArgumentException("Public key is not an RSA key");
                }
                
                return (RSAPublicKey) publicKey;
            } else {
                throw new IllegalArgumentException(
                    "Expected SubjectPublicKeyInfo but got: " + object.getClass().getName());
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load public key from PEM", e);
        }
    }
}
