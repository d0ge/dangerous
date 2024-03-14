package one.d4d.dangerous.crypto;

import one.d4d.dangerous.*;
import one.d4d.dangerous.keys.SecretKey;

import java.util.EnumSet;

public class DjangoTokenSigner extends DangerousTokenSigner {

    public DjangoTokenSigner(SecretKey key) {
        super(key);
        this.knownDerivations = EnumSet.of(Derivation.DJANGO);
    }

    public DjangoTokenSigner(byte[] secret_key, byte[] salt, byte[] sep) {
        this(Algorithms.SHA1, Derivation.DJANGO, MessageDerivation.NONE, MessageDigestAlgorithm.SHA1, secret_key, salt, sep);
    }

    public DjangoTokenSigner(
            Algorithms algorithm,
            Derivation keyDerivation,
            MessageDerivation messageDerivation,
            MessageDigestAlgorithm digest,
            byte[] secret_key,
            byte[] salt,
            byte[] sep) {
        super(algorithm, keyDerivation, messageDerivation, digest, secret_key, salt, sep);
        this.knownDerivations = EnumSet.of(Derivation.DJANGO);
    }
}
