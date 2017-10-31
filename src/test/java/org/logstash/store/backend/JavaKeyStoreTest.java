package org.logstash.store.backend;


import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.logstash.secret.SecretIdentifier;
import org.logstash.store.SecretStoreException;

import java.nio.file.Path;
import java.security.KeyStoreException;
import java.util.UUID;

public class JavaKeyStoreTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

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
    public void test() throws KeyStoreException, SecretStoreException, InterruptedException {

        char[] initSecret = keyStore.retrieveSecret(new SecretIdentifier.Builder("logstash").key("init").build());
        System.out.println(initSecret);

        SecretIdentifier fooId = new SecretIdentifier.Builder("logstash").key("foo").build();
        keyStore.persistSecret(fooId, "foo".toCharArray());
        System.out.println(keyStore.retrieveSecret(fooId));

        keyStore.list().stream().forEach(x -> System.out.println(x));

        keyStore.purgeSecret(fooId);
        System.out.println("***************");
        keyStore.list().stream().forEach(x -> System.out.println(x));
    }

}