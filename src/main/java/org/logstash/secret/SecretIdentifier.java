package org.logstash.secret;


//urn:<namespace>:secret:v1:<scope>:<key>


import java.util.Locale;

public class SecretIdentifier {


    private final String scope;


    private final String key;


    private final String namespace;


    public static class Builder {


        private String scope;

        private final String namespace;

        private String key = null;

        public Builder(String namespace) {
            this.namespace = validate(namespace, "namespace");
        }

        public Builder key(String key) {
            this.key = validate(key, "key");
            return this;
        }

        public Builder scope(String scope) {
            this.scope = validate(scope, "scope");
            return this;
        }

        public SecretIdentifier build() {
            return new SecretIdentifier(this);
        }

        private String validate(String part, String partName) {
            if (part != null && part.contains(":")) {
                throw new IllegalArgumentException(String.format("{} may not contain an colon (:)", partName));
            }
            return part;
        }
    }


    public String getKey() {
        return key;
    }

    public String getScope() {
        return scope;
    }


    public String getNamespace() {
        return namespace;
    }

    public String getUrnVersion() {
        //Hard coding v1 as the version of this URN. This allows passive changes to the URN itself.
        return "v1";
    }


    private SecretIdentifier(Builder builder) {
        this.namespace = builder.namespace;
        this.scope = builder.scope;
        this.key = builder.key;
    }

    //TODO: prevent contents from containing colon
    public String toExternalForm() {
        StringBuilder sb = new StringBuilder(100);
        sb.append("urn").append(":");
        sb.append(this.namespace).append(":");
        sb.append("secret").append(":");
        sb.append(this.getUrnVersion()).append(":");
        sb.append(this.scope == null ? "-" : this.scope.toLowerCase(Locale.US)).append(":");
        sb.append(this.key == null ? "-" : this.key.toLowerCase(Locale.US)).append(":");

        return sb.toString();
    }

    public static SecretIdentifier fromExternalForm(String urn) {
        String[] tokens = urn.split(":");
        String namespace = tokens[1];
        String scope = tokens[4];
        String key = tokens[5];
        Builder builder = new Builder(namespace);
        builder.scope(scope);
        builder.key(key);
        return builder.build();

    }

    @Override
    public String toString() {
        return "SecretIdentifier{" +
                "namespace='" + namespace + '\'' +
                ", scope='" + scope + '\'' +
                ", key='" + key + '\'' +
                '}';
    }


}
