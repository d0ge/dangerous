package one.d4d.dangerous.keys;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import one.d4d.dangerous.*;

public class SecretKey implements Key {
    @Expose
    @SerializedName("keyId")
    private final String keyId;
    @Expose
    @SerializedName("secret")
    private final String secret;
    @Expose
    @SerializedName("salt")
    private final String salt;
    @Expose
    @SerializedName("separator")
    private final String separator;
    @Expose
    @SerializedName("digestMethod")
    private final Algorithms digestMethod;
    @Expose
    @SerializedName("keyDerivation")
    private final Derivation keyDerivation;
    @Expose
    @SerializedName("messageDerivation")
    private final MessageDerivation messageDerivation;
    @Expose
    @SerializedName("messageDigestAlgorythm")
    private final MessageDigestAlgorithm messageDigestAlgorithm;

    public SecretKey(
            String keyId,
            String secret,
            String salt,
            String separator,
            Algorithms digestMethod,
            Derivation keyDerivation,
            MessageDerivation messageDerivation,
            MessageDigestAlgorithm messageDigestAlgorithm) {
        this.keyId = keyId;
        this.secret = secret;
        this.salt = salt;
        this.separator = separator;
        this.digestMethod = digestMethod;
        this.keyDerivation = keyDerivation;
        this.messageDerivation = messageDerivation;
        this.messageDigestAlgorithm = messageDigestAlgorithm;
    }

    public String getSecret() {
        return secret;
    }

    public String getSalt() {
        return salt;
    }

    public String getSeparator() {
        return separator;
    }

    public Algorithms getDigestMethod() {
        return digestMethod;
    }

    public Derivation getKeyDerivation() {
        return keyDerivation;
    }

    public MessageDerivation getMessageDerivation() {
        return messageDerivation;
    }

    public MessageDigestAlgorithm getMessageDigestAlgorythm() {
        return messageDigestAlgorithm;
    }

    @Override
    public String getID() {
        return keyId;
    }

    @Override
    public String toString() {
        return keyId;
    }

    public String toJSONString() {
        return "{" +
                "keyId='" + keyId + '\'' +
                ", secret='" + secret + '\'' +
                ", salt='" + salt + '\'' +
                ", separator='" + separator + '\'' +
                ", digestMethod=" + digestMethod +
                ", keyDerivation=" + keyDerivation +
                ", messageDigestAlgorythm=" + messageDigestAlgorithm +
                '}';
    }
}
