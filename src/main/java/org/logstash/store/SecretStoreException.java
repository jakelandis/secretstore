package org.logstash.store;

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
}
