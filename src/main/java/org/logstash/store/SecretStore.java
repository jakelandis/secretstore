package org.logstash.store;

import org.logstash.secret.SecretIdentifier;

import java.util.Collection;


public interface SecretStore {

    char[] retrieveSecret(SecretIdentifier id) throws SecretStoreException;

    void purgeSecret(SecretIdentifier id) throws SecretStoreException;

    void persistSecret(SecretIdentifier id, char[] secret) throws SecretStoreException;

    Collection<SecretIdentifier> list();

}
