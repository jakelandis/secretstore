package org.logstash.store.backend;

import org.logstash.secret.SecretIdentifier;
import org.logstash.store.SecretStore;
import org.logstash.store.SecretStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

//NOT for high volume lookups or large datasets
//Simple
public final class JavaKeyStore implements SecretStore {
    private KeyStore keyStore;

    private final Path keyStorePath;

    final ProtectionParameter protectionParameter;
    private final static Logger LOGGER = LoggerFactory.getLogger(JavaKeyStore.class);
    private final char[] keyStorePass;

    public JavaKeyStore(Path keyStorePath, char[] keyStorePass) throws SecretStoreException {
        try {
            this.keyStorePath = keyStorePath;
            String keyStoreType = System.getProperty("java.keystore.type", "pkcs12");
            this.keyStore = KeyStore.getInstance(keyStoreType);
            this.keyStorePass = keyStorePass;

            protectionParameter = new PasswordProtection(keyStorePass);

            try (final InputStream is = Files.newInputStream(keyStorePath)) {
                keyStore.load(is, keyStorePass);
            } catch (NoSuchFileException noSuchFileException) {
                LOGGER.warn("Keystore not found at {}. Creating new keystore.", keyStorePath.toAbsolutePath().toString());

                try {
                    try (final OutputStream os = Files.newOutputStream(keyStorePath)) {
                        keyStore = KeyStore.Builder.newInstance(keyStoreType, null, protectionParameter).getKeyStore();
                        SecretIdentifier secretIdentifier = new SecretIdentifier("init");
                        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
                        SecretKey secretKey = factory.generateSecret(new PBEKeySpec(LocalDateTime.now().toString().toCharArray()));
                        keyStore.setEntry(secretIdentifier.toExternalForm(), new KeyStore.SecretKeyEntry(secretKey), protectionParameter);
                        keyStore.store(os, keyStorePass);

                        //todo: enforce file permissions
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }catch (Exception e){
            throw new SecretStoreException();
        }
    }

    @Override
    public char[] retrieveSecret(SecretIdentifier identifier) throws SecretStoreException {
        try {
            try (final InputStream is = Files.newInputStream(keyStorePath)) {
                keyStore.load(is, keyStorePass);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
                KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(identifier.toExternalForm(), protectionParameter);
                PBEKeySpec passwordBasedKeySpec = (PBEKeySpec) factory.getKeySpec(secretKeyEntry.getSecretKey(), PBEKeySpec.class);
                char[] secret = passwordBasedKeySpec.getPassword().clone();
                passwordBasedKeySpec.clearPassword();
                return secret;
            }
        } catch (Exception e) {
            throw new SecretStoreException();
        }
    }

    @Override
    public void purgeSecret(SecretIdentifier identifier) throws SecretStoreException {
        try {
            try (final InputStream is = Files.newInputStream(keyStorePath)) {
                keyStore.load(is, keyStorePass);
                keyStore.deleteEntry(identifier.toExternalForm());
            }
        } catch (Exception e) {
            throw new SecretStoreException();
        }
    }

    @Override
    public void persistSecret(SecretIdentifier identifier, char[] secret) throws SecretStoreException {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
            PBEKeySpec passwordBasedKeySpec = new PBEKeySpec(secret);
            SecretKey secretKey = factory.generateSecret(passwordBasedKeySpec);
            keyStore.setEntry(identifier.toExternalForm(), new KeyStore.SecretKeyEntry(secretKey), protectionParameter);
            try (final OutputStream os = Files.newOutputStream(keyStorePath)) {
                keyStore.store(os, keyStorePass);
                passwordBasedKeySpec.clearPassword();
                clearSecret(secret);

            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public Collection<SecretIdentifier> list() {
        Set<SecretIdentifier> identifiers = new HashSet<>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                identifiers.add(SecretIdentifier.fromExternalForm(alias));
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return identifiers;
    }


    private void clearSecret(char[] secret) {
        if (secret != null) {
            for (int i = 0; i < secret.length; ++i) {
                secret[i] = '\0';
            }
            secret = null;
        }
    }

}
