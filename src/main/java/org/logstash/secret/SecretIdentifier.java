package org.logstash.secret;


import java.util.Locale;

/**
 * <p>A URN based identifier for a given secret. The URN is constructed as such: {@code urn:logstash:secret:<key>}</p>
 */
public class SecretIdentifier {

    private final String key;

    public SecretIdentifier(String key) {
        this.key = validate(key, "key");
    }


    //TODO: escape don't error !
    private String validate(String part, String partName) {
        if (part != null && part.contains(":")) {
            throw new IllegalArgumentException(String.format("{} may not contain an colon (:)", partName));
        }
        return part;
    }


    public String getKey() {
        return key;
    }


    public String toExternalForm() {
        StringBuilder sb = new StringBuilder(100);
        sb.append("urn").append(":");
        sb.append("logstash").append(":");
        sb.append("secret").append(":");
        sb.append(this.key == null ? "-" : this.key.toLowerCase(Locale.US));

        return sb.toString();
    }

    public static SecretIdentifier fromExternalForm(String urn) {
        String[] tokens = urn.split(":");
        String key = tokens[tokens.length - 1];
        return new SecretIdentifier(key);

    }

    @Override
    public String toString() {
        return toExternalForm();
    }
}
