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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * <p>Java Key Store implementation for the {@link SecretStore}.</p>
 * <p>Note this implementation should not be used for high volume or large datasets.</p>
 * <p>This class is threadsafe.</p>
 */
public final class JavaKeyStore implements SecretStore {
    static final String MARKER = "logstash-key-store";
    private final static Logger LOGGER = LoggerFactory.getLogger(JavaKeyStore.class);
    private final char[] keyStorePass;
    private final Path keyStorePath;
    private final ProtectionParameter protectionParameter;
    private final Lock readLock;
    private final Lock writeLock;
    private KeyStore keyStore;


    /**
     * Constructor - will create the keystore if it does not exist
     *
     * @param keyStorePath The full path to the java keystore
     * @param keyStorePass The password to the keystore
     * @throws SecretStoreException if errors occur while trying to create or access the keystore
     */
    public JavaKeyStore(Path keyStorePath, char[] keyStorePass) {
        try {
            this.keyStorePath = keyStorePath;
            String keyStoreType = System.getProperty("java.keystore.type", "pkcs12");
            this.keyStore = KeyStore.getInstance(keyStoreType);
            this.keyStorePass = keyStorePass;
            ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
            readLock = readWriteLock.readLock();
            writeLock = readWriteLock.writeLock();
            this.protectionParameter = new PasswordProtection(keyStorePass);
            SecretIdentifier logstashMarker = new SecretIdentifier(MARKER);

            try (final InputStream is = Files.newInputStream(keyStorePath)) {
                keyStore.load(is, keyStorePass);
                byte[] marker = retrieveSecret(logstashMarker);
                if (marker == null) {
                    throw new SecretStoreException.NotLogstashKeyStore("Found a keystore, but is not a logstash keystore");
                }
            } catch (NoSuchFileException noSuchFileException) {
                LOGGER.warn("Keystore not found at {}. Creating new keystore.", keyStorePath.toAbsolutePath().toString());

                //create the keystore on disk with a default entry to identify this as a logstash keystore
                try (final OutputStream os = Files.newOutputStream(keyStorePath)) {
                    keyStore = KeyStore.Builder.newInstance(keyStoreType, null, protectionParameter).getKeyStore();
                    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
                    byte[] base64 = Base64.getEncoder().encode(MARKER.getBytes(StandardCharsets.UTF_8));
                    SecretKey secretKey = factory.generateSecret(new PBEKeySpec(asciiBytesToChar(base64)));
                    keyStore.setEntry(logstashMarker.toExternalForm(), new KeyStore.SecretKeyEntry(secretKey), protectionParameter);
                    keyStore.store(os, keyStorePass);

                    PosixFileAttributeView attrs = Files.getFileAttributeView(keyStorePath, PosixFileAttributeView.class);
                    if (attrs != null) {
                        attrs.setPermissions(PosixFilePermissions.fromString("rw-rw----"));
                    }
                }
            }
        } catch (Exception e) {
            throw new SecretStoreException("Error while construction the JavaKeyStore", e);
        }
    }

    /**
     * Attempt to keep the secret data out of the heap.
     *
     * @param secret the secret to zero out
     */
    private void clearSecret(byte[] secret) {
        if (secret != null) {
            for (int i = 0; i < secret.length; ++i) {
                secret[i] = '\0';
            }
            secret = null;
        }
    }

    @Override
    public Collection<SecretIdentifier> list() {
        Set<SecretIdentifier> identifiers = new HashSet<>();
        try {
            readLock.lock();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                identifiers.add(SecretIdentifier.fromExternalForm(alias));
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } finally {
            readLock.unlock();
        }
        return identifiers;
    }

    @Override
    public void persistSecret(SecretIdentifier identifier, byte[] secret) {
        try {
            writeLock.lock();
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
            //the password is required to be ascii encoded
            byte[] base64 = Base64.getEncoder().encode(secret);
            PBEKeySpec passwordBasedKeySpec = new PBEKeySpec(asciiBytesToChar(base64));
            SecretKey secretKey = factory.generateSecret(passwordBasedKeySpec);
            keyStore.setEntry(identifier.toExternalForm(), new KeyStore.SecretKeyEntry(secretKey), protectionParameter);
            try (final OutputStream os = Files.newOutputStream(keyStorePath)) {
                keyStore.store(os, keyStorePass);
            } finally {
                passwordBasedKeySpec.clearPassword();
                clearSecret(secret);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            writeLock.unlock();
        }

    }

    @Override
    public void purgeSecret(SecretIdentifier identifier) {
        try {
            writeLock.lock();
            try (final InputStream is = Files.newInputStream(keyStorePath)) {
                keyStore.load(is, keyStorePass);
                keyStore.deleteEntry(identifier.toExternalForm());
            }
            try (final OutputStream os = Files.newOutputStream(keyStorePath)) {
                keyStore.store(os, keyStorePass);
            }
        } catch (Exception e) {
            throw new SecretStoreException("TODO", e);
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public byte[] retrieveSecret(SecretIdentifier identifier) {
        if (identifier != null && identifier.getKey() != null && !identifier.getKey().isEmpty()) {
            try {
                readLock.lock();
                try (final InputStream is = Files.newInputStream(keyStorePath)) {
                    keyStore.load(is, keyStorePass);
                    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBE");
                    KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(identifier.toExternalForm(), protectionParameter);
                    //not found
                    if (secretKeyEntry == null) {
                        return null;
                    }
                    PBEKeySpec passwordBasedKeySpec = (PBEKeySpec) factory.getKeySpec(secretKeyEntry.getSecretKey(), PBEKeySpec.class);
                    //base64 encoded char[]
                    char[] secret = passwordBasedKeySpec.getPassword().clone();
                    passwordBasedKeySpec.clearPassword();
                    return Base64.getDecoder().decode(asciiCharToBytes(secret));
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new SecretStoreException("TODO", e);
            } finally {
                readLock.unlock();
            }
        }
        return null;
    }

    private char[] asciiBytesToChar(byte[] bytes){
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            chars[i] = (char) bytes[i];
            bytes[i] = '\0';
        }
        return chars;
    }

    private byte[] asciiCharToBytes(char[] chars){
        byte[] bytes = new byte[chars.length];
        for (int i = 0; i < chars.length; i++) {
            bytes[i] = (byte) chars[i];
            chars[i] = '\0';
        }
        return bytes;

    }

}
