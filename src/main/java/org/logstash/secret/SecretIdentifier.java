package org.logstash.secret;


import java.util.Locale;

/**
 * <p>A URN based identifier for a given secret. The URN is constructed as such: {@code urn:logstash:secret:v1:<key>}</p>
 * <p><em>Note - v1 is the version of the URN (not the key). This allows for passive changes to the URN for anything to the right of v1</em></p>
 */
public class SecretIdentifier {

    private final String key;
    private final String VERSION = "v1";

    /**
     * Constructor
     *
     * @param key The unique part of the identifier. This is the key to reference the secret, and the key itself should not be sensitive. For example: {@code db.pass}
     */
    public SecretIdentifier(String key) {
        this.key = validateWithTransform(key, "key");
    }

    /**
     * Converts an external URN format to a {@link SecretIdentifier} object.
     *
     * @param urn The {@link String} formatted identifier obtained originally from {@link SecretIdentifier#toExternalForm()}
     * @return The {@link SecretIdentifier} object used to identify secrets.
     */
    public static SecretIdentifier fromExternalForm(String urn) {
        String[] tokens = urn.split(":");
        String key = tokens[tokens.length - 1];
        return new SecretIdentifier(key);
    }

    /**
     * Get the key (unique part) of the identifier
     *
     * @return the unique part of the identifier
     */
    public String getKey() {
        return key;
    }

    /**
     * Converts this object to a format acceptable external {@link String} format. Note - no gauruntees are made with respect to encoding or safe use. For example, the external
     * format may not be URL safely encoded.
     *
     * @return the externally formatted {@link String}
     */
    public String toExternalForm() {
        StringBuilder sb = new StringBuilder(100);
        sb.append("urn").append(":");
        sb.append("logstash").append(":");
        sb.append("secret").append(":");
        sb.append(VERSION).append(":");
        sb.append(this.key == null ? "-" : this.key.toLowerCase(Locale.US));
        return sb.toString();
    }

    @Override
    public String toString() {
        return toExternalForm();
    }

    /**
     * Minor validation and transformation on input. Converts ":" to "_" to avoid URN conflicts, and downcases the parts
     *
     * @param part     The part of the URN to validate
     * @param partName The name of the part used for logging.
     * @return The validated and transformed part.
     */
    private String validateWithTransform(String part, String partName) {
        if (part == null || part.isEmpty()) {
            throw new IllegalArgumentException(String.format("{} may not be null or empty", partName));
        }
        return part.replace(":", "_").toLowerCase(Locale.US);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SecretIdentifier that = (SecretIdentifier) o;

        if (key != null ? !key.equals(that.key) : that.key != null) return false;
        return VERSION != null ? VERSION.equals(that.VERSION) : that.VERSION == null;
    }

    @Override
    public int hashCode() {
        int result = key != null ? key.hashCode() : 0;
        result = 31 * result + (VERSION != null ? VERSION.hashCode() : 0);
        return result;
    }
}
