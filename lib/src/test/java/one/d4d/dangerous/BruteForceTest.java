package one.d4d.dangerous;

import com.google.gson.Gson;
import one.d4d.dangerous.crypto.DangerousTokenSigner;
import one.d4d.dangerous.keys.SecretKey;
import one.d4d.dangerous.model.SignedToken;
import one.d4d.dangerous.utils.GsonHelper;
import one.d4d.dangerous.utils.SignedTokenObjectFinder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.*;

public class BruteForceTest {

    private static BruteForce getBruteForce(SignedToken token) {
        byte[] sep = new byte[]{'.'};
        DangerousTokenSigner s = new DangerousTokenSigner(sep);
        token.setSigner(s);
        final Set<String> secrets = new HashSet<>(List.of("secret"));
        final Set<String> salts = new HashSet<>(List.of("salt"));
        final List<SecretKey> knownKeys = new ArrayList<>();

        return new BruteForce(secrets, salts, knownKeys, Attack.FAST, token);
    }
    @Test
    void BruteForceAttack() {
        Assertions.assertDoesNotThrow(() -> {
            Optional<SignedToken> optionalSignedToken = SignedTokenObjectFinder.parseToken("e30.Zm17Ig.Ajtll0l5CXAy9Yqgy-vvhF05G28");
            if (optionalSignedToken.isPresent()) {
                BruteForce bf = getBruteForce(optionalSignedToken.get());
                SecretKey sk = bf.parallel();
                Assertions.assertNotNull(sk);
            } else {
                Assertions.fail("Token not found.");
            }
        });
    }

    @Test
    void BruteForceMultiThreatAttack() {
        Assertions.assertDoesNotThrow(() -> {
            Optional<SignedToken> optionalSignedToken = SignedTokenObjectFinder.parseToken("e30.Zm17Ig.Ajtll0l5CXAy9Yqgy-vvhF05G28");
            if (optionalSignedToken.isPresent()) {
                BruteForce bf = getBruteForce(optionalSignedToken.get());
                SecretKey sk = bf.parallel();
                Assertions.assertNotNull(sk);
            } else {
                Assertions.fail("Token not found.");
            }
        });
    }

}
