package one.d4d.dangerous.model;

import com.nimbusds.jwt.JWTClaimsSet;
import one.d4d.dangerous.*;
import one.d4d.dangerous.crypto.ExpressTokenSigner;
import one.d4d.dangerous.crypto.TornadoTokenSigner;
import one.d4d.dangerous.utils.HexUtils;
import one.d4d.dangerous.utils.Utils;

import java.util.Base64;

public class TornadoSignedToken extends SignedToken {
    public static String formatVersion = "2";
    public static String keyVersion = "0";
    public byte separator = (byte) '|';
    public String timestamp;
    public String name;
    public String value;

    public TornadoSignedToken(String timestamp, String name, String value, String signature) {
        super(String.join(
                "|",
                formatVersion,
                formatField(keyVersion),
                formatField(timestamp),
                formatField(name),
                formatField(value),
                ""));
        this.timestamp = timestamp;
        this.name = name;
        this.value = value;
        this.signature = signature;
        this.signer = new TornadoTokenSigner();
    }

    private static String formatField(String field) {
        return String.format("%d:%s", field.length(), field);
    }

    public void setSigner(ExpressTokenSigner signer) {
        this.signer = signer;
    }


    public void unsign() throws BadSignatureException {
        signer.fast_unsign(getEncodedMessage().getBytes(), this.signature.getBytes());
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        try {
            byte[] json = Utils.base64Decompress(this.value.getBytes());
            return new String(json);
        } catch (Exception e) {
            return value;
        }
    }

    public String getTimestamp() {
        return Utils.timestampSeconds(timestamp);
    }

    public byte[] getSeparator() {
        return new byte[]{separator};
    }

    @Override
    public String serialize() {
        return String.join(
                "|",
                formatVersion,
                formatField(keyVersion),
                formatField(timestamp),
                formatField(name),
                formatField(value),
                signature);
    }

    @Override
    public void resign() throws Exception {
        byte[] value = message.getBytes();
        this.signature = HexUtils.encodeHex(signer.get_signature_unsafe(value));
    }

    @Override
    public void setClaims(JWTClaimsSet claims) {
        this.value = new String(Base64.getUrlEncoder().encode(claims.toString().getBytes()));
        this.message = String.join(
                "|",
                formatVersion,
                formatField(keyVersion),
                formatField(timestamp),
                formatField(name),
                formatField(value),
                "");
    }
}
