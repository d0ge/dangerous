package one.d4d.dangerous.model;

import one.d4d.dangerous.*;
import one.d4d.dangerous.utils.Utils;

public class DjangoSignedToken extends DangerousSignedToken {

    public DjangoSignedToken(byte[] separator, String payload, String timestamp, String signature) {
        super(separator, payload, timestamp, signature, Algorithms.SHA1, Derivation.DJANGO, MessageDerivation.NONE, MessageDigestAlgorithm.SHA1);
    }

    @Override
    public String toString() {
        try {
            StringBuilder sb = new StringBuilder();
            byte[] json = Utils.base64Decompress(this.payload.getBytes());
            sb.append(new String(json)).append(new String(this.separator));
            sb.append(Utils.base62timestamp(this.timestamp.getBytes())).append(new String(this.separator));
            sb.append(this.signature);
            return sb.toString();
        } catch (Exception e) {
            return String.format("%s%s%s%s%s", payload, new String(separator), timestamp, new String(separator), signature);
        }
    }

    @Override
    public String getTimestamp() {
        try {
            return Utils.base62timestamp(timestamp.getBytes());
        } catch (Exception e) {
            return Utils.timestamp(timestamp.getBytes());
        }
    }
}
