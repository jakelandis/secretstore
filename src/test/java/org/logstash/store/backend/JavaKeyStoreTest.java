package org.logstash.store.backend;


import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import org.logstash.secret.SecretIdentifier;
import org.logstash.store.SecretStoreException;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.instanceOf;

public class JavaKeyStoreTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Rule
    public ExpectedException thrown = ExpectedException.none();


    private Path keyStorePath;
    private char[] keyStorePass;
    private JavaKeyStore keyStore;


    @Before
    public void setup() throws Exception {
        keyStorePath = folder.newFolder().toPath().resolve("logstash.keystore");
        keyStorePass = UUID.randomUUID().toString().toCharArray();
        keyStore = new JavaKeyStore(keyStorePath, keyStorePass);
    }

    @Test
    public void isLogstashKeystore() throws Exception {
        //newly created
        byte[] marker = keyStore.retrieveSecret(new SecretIdentifier(JavaKeyStore.MARKER));
        assertThat(new String(marker, StandardCharsets.UTF_8)).isEqualTo(JavaKeyStore.MARKER);

        //exiting
        //TODO: create new keystore with base64 encoded values
        JavaKeyStore existingKeyStore = new JavaKeyStore(Paths.get(this.getClass().getClassLoader().getResource("logstash.keystore").toURI()), "mypassword".toCharArray());
        marker = existingKeyStore.retrieveSecret(new SecretIdentifier(JavaKeyStore.MARKER));
        assertThat(new String(marker, StandardCharsets.UTF_8)).isEqualTo(JavaKeyStore.MARKER);
    }

    @Test
    public void notLogstashKeystore() throws Exception {
        thrown.expect(SecretStoreException.class);
        thrown.expectCause(instanceOf(SecretStoreException.NotLogstashKeyStore.class));
        new JavaKeyStore(Paths.get(this.getClass().getClassLoader().getResource("not.a.logstash.keystore").toURI()), "mypassword".toCharArray());
    }

    @Test
    public void wrongPassword() throws Exception {
        thrown.expect(SecretStoreException.class);
        new JavaKeyStore(Paths.get(this.getClass().getClassLoader().getResource("logstash.keystore").toURI()), "wrongpassword".toCharArray());
    }

    @Test
    public void tamperedKeystore() throws Exception {
        //this ends up testing the Java's KeyStore, not the code here....but important to test regardless
        thrown.expect(SecretStoreException.class);
        byte[] keyStoreAsBytes = Files.readAllBytes(keyStorePath);
        //bump the middle byte by 1
        int tamperLocation = keyStoreAsBytes.length / 2;
        keyStoreAsBytes[tamperLocation] = (byte) (keyStoreAsBytes[tamperLocation] + 1);
        Path tamperedPath = folder.newFolder().toPath().resolve("tampered.logstash.keystore");
        Files.write(tamperedPath, keyStoreAsBytes);
        new JavaKeyStore(tamperedPath, keyStorePass);
    }

    @Test
    public void readExisting() throws Exception {
        JavaKeyStore existingKeyStore = new JavaKeyStore(Paths.get(this.getClass().getClassLoader().getResource("logstash.keystore").toURI()), "mypassword".toCharArray());
        //contents of the existing is a-z for both the key and value
        for (int i = 65; i <= 90; i++) {
            char[] expected = new char[]{(char) i};
            SecretIdentifier id = new SecretIdentifier(String.valueOf(expected));
            assertThat(existingKeyStore.retrieveSecret(id)).isEqualTo(expected);
        }
    }

    /**
     * Uses a freshly created keystore to write 26 entries, list them, read them, and delete them.
     */
    @Test
    public void readWriteListDelete() {

        Set<String> values = new HashSet<>(27);
        Set<SecretIdentifier> keys = new HashSet<>(27);
        SecretIdentifier markerId = new SecretIdentifier(JavaKeyStore.MARKER);
        //add the marker
        keys.add(markerId);
        values.add(JavaKeyStore.MARKER);
        //a-z key and value
        for (int i = 65; i <= 90; i++) {
            byte[] expected = new byte[]{(byte) i};
            values.add(new String(expected, StandardCharsets.UTF_8));
            SecretIdentifier id = new SecretIdentifier(new String(expected, StandardCharsets.UTF_8));
            keyStore.persistSecret(id, expected);
            keys.add(id);
        }
        Collection<SecretIdentifier> foundIds = keyStore.list();
        assertThat(keyStore.list().size()).isEqualTo(26 + 1);
        assertThat(values.size()).isEqualTo(26 + 1);
        assertThat(keys.size()).isEqualTo(26 + 1);

        foundIds.stream().forEach(id -> assertThat(keys).contains(id));
        foundIds.stream().forEach(id -> assertThat(values).contains(new String(keyStore.retrieveSecret(id), StandardCharsets.UTF_8)));

        foundIds.stream().filter(id -> !id.equals(markerId)).forEach(id -> keyStore.purgeSecret(id));

        assertThat(keyStore.list().size()).isEqualTo(1);
        assertThat(keyStore.list().stream().findFirst().get()).isEqualTo(markerId);

    }

    @Test
    public void testPermissions() {

    }

    @Test
    public void canUseKeyTool() {
        // keytool -list -keystore logstash.keystore -storepass mypassword -storetype PKCS12 -v

    }

    @Test
    public void testNonAscii() throws Exception {
        int[] codepoints = {0xD83E, 0xDD21, 0xD83E, 0xDD84};
        String nonAscii = new String(codepoints, 0, codepoints.length);
        SecretIdentifier id = new SecretIdentifier(nonAscii);
        keyStore.persistSecret(id, nonAscii.getBytes(StandardCharsets.UTF_8));
        assertThat(new String(keyStore.retrieveSecret(id), StandardCharsets.UTF_8)).isEqualTo(nonAscii);
    }


}