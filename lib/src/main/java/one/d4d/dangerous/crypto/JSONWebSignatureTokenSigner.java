package one.d4d.dangerous.crypto;

import one.d4d.dangerous.*;
import one.d4d.dangerous.keys.SecretKey;

import java.util.EnumSet;

public class JSONWebSignatureTokenSigner extends TokenSigner {

    public JSONWebSignatureTokenSigner(SecretKey key) {
        super(key);
        this.keyDerivation = Derivation.NONE;
        this.messageDigestAlgorithm = MessageDigestAlgorithm.NONE;
        this.knownDerivations = EnumSet.of(Derivation.NONE);
    }

    public JSONWebSignatureTokenSigner(byte[] sep) {
        super(Algorithms.SHA256, Derivation.NONE, MessageDerivation.NONE, MessageDigestAlgorithm.NONE, new byte[]{}, new byte[]{}, sep);
        this.knownDerivations = EnumSet.of(Derivation.NONE);
    }
}
