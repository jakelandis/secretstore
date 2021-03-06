package org.logstash.store;

import org.logstash.secret.SecretIdentifier;

import java.util.Collection;

/**
 * <p>Contract with a store that can persist, retrieve, and purge sensitive data.</p>
 * <p>Implementations <strong>MUST</strong> ensure proper security for the storage of the secrets.</p>
 * <p>Any of the methods may throw a {@link SecretStoreException} if errors are encountered. </p>
 */
public interface SecretStore {

    /**
     * Gets all of the known {@link SecretIdentifier}
     *
     * @return a Collection of {@link SecretIdentifier}
     */
    Collection<SecretIdentifier> list();

    /**
     * Persist a secret to the store. Implementations should overwrite existing secrets with same identifier without error unless explicitly documented otherwise.
     *
     * @param id     The {@link SecretIdentifier} to identify the secret to persist
     * @param secret The byte[] representation of the secret.
     */
    void persistSecret(SecretIdentifier id, byte[] secret);

    /**
     * Purges the secret from the store.
     *
     * @param id The {@link SecretIdentifier} to identify the secret to purge
     */
    void purgeSecret(SecretIdentifier id);

    /**
     * Retrieves a secret.
     *
     * @param id The {@link SecretIdentifier} to identify the secret to retrieve
     * @return the byte[] of the secret, null if no secret is found.
     */
    byte[] retrieveSecret(SecretIdentifier id);

}
