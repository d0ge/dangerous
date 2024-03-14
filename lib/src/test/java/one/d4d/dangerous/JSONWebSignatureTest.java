package one.d4d.dangerous;

import com.google.gson.Gson;
import one.d4d.dangerous.keys.SecretKey;
import one.d4d.dangerous.model.JSONWebSignature;
import one.d4d.dangerous.model.SignedToken;
import one.d4d.dangerous.utils.ClaimsUtils;
import one.d4d.dangerous.utils.GsonHelper;
import one.d4d.dangerous.utils.SignedTokenObjectFinder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class JSONWebSignatureTest {
    @Test
    void JSONWebSignatureParserTest() {
        final Set<String> secrets = new HashSet<>(List.of("your-256-bit-secret"));
        final Set<String> salts = new HashSet<>(List.of("salt"));
        final List<SecretKey> knownKeys = new ArrayList<>();
        String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseJSONWebSignature(value);
        if (optionalToken.isPresent()) {
            JSONWebSignature token = (JSONWebSignature) optionalToken.get();
            BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.FAST, token);
            SecretKey sk = bf.parallel();
            Assertions.assertNotNull(sk);
        } else {
            Assertions.fail("Token not found.");
        }
    }

    @Test
    void JSONWebSignatureClaimsTest() {
        try {
            final Set<String> secrets = new HashSet<>(List.of("secret"));
            final Set<String> salts = new HashSet<>(List.of("salt"));
            final List<SecretKey> knownKeys = new ArrayList<>();
            URL target = new URL("https://d4d.one/");
            SecretKey key = new SecretKey("1", "secret", "", ".", Algorithms.SHA256, Derivation.NONE, MessageDerivation.NONE, MessageDigestAlgorithm.NONE);
            String value = ClaimsUtils.generateJSONWebToken(target, ClaimsUtils.DEFAULT_USERNAME, key);
            Optional<SignedToken> optionalToken = SignedTokenObjectFinder.parseJSONWebSignature(value);
            if (optionalToken.isPresent()) {
                JSONWebSignature token = (JSONWebSignature) optionalToken.get();
                BruteForce bf = new BruteForce(secrets, salts, knownKeys, Attack.FAST, token);
                SecretKey sk = bf.parallel();
                Assertions.assertNotNull(sk);
            } else {
                Assertions.fail("Token not found.");
            }
        } catch (MalformedURLException | BadPayloadException e) {
            throw new RuntimeException(e);
        }
    }
}
