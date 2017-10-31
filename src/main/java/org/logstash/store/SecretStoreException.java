package org.logstash.store;

public class SecretStoreException extends Exception {

    //thrown when duplicate keys are found
    class DuplicateKey extends SecretStoreException{

    }

    //thrown when trying to persist using a partial Urn
    class PartialUrn extends SecretStoreException{

    }
    //thrown when can not find Urn in store
    class UnsatisfiableUrn extends SecretStoreException{

    }
}
