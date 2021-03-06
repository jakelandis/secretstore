package org.logstash.store;

import org.logstash.secret.SecretIdentifier;

/**
 * Exceptions when working a {@link SecretStore}
 */
public class SecretStoreException extends RuntimeException {

    public SecretStoreException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecretStoreException(String message) {
        super(message);
    }

    static public class NotLogstashKeyStore extends SecretStoreException {
        public NotLogstashKeyStore(String message) {
            super(message);
        }
    }

    static public class RetrievalException extends SecretStoreException {
        public RetrievalException(SecretIdentifier secretIdentifier, Throwable cause) {
            super(String.format("Error while trying to retrieve secret %s", secretIdentifier.toExternalForm(), cause));
        }
    }

    static public class PersistException extends SecretStoreException {
        public PersistException(SecretIdentifier secretIdentifier, Throwable cause) {
            super(String.format("Error while trying to store secret %s", secretIdentifier.toExternalForm(), cause));
        }
    }

    static public class PurgeException extends SecretStoreException {
        public PurgeException(SecretIdentifier secretIdentifier, Throwable cause) {
            super(String.format("Error while trying to purge secret %s", secretIdentifier.toExternalForm(), cause));
        }
    }

}
