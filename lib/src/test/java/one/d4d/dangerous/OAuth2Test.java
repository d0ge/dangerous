package one.d4d.dangerous;

import com.google.gson.Gson;
import one.d4d.dangerous.crypto.DangerousTokenSigner;
import one.d4d.dangerous.crypto.OauthProxyTokenSigner;
import one.d4d.dangerous.keys.SecretKey;
import one.d4d.dangerous.model.OauthProxySignedToken;
import one.d4d.dangerous.model.SignedToken;
import one.d4d.dangerous.utils.GsonHelper;
import one.d4d.dangerous.utils.SignedTokenObjectFinder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.*;

public class OAuth2Test {
    private static BruteForce getBruteForce(SignedToken token) {
        final Set<String> secrets = Set.of("j76h5PEMx3FIGr3caArJ5g==");
        final Set<String> salts = Set.of("salt");
        final List<SecretKey> knownKeys = new ArrayList<>();

        return new BruteForce(secrets, salts, knownKeys, Attack.Deep, token);
    }

    @Test
    void OauthProxyParserTest() {
        byte[] secret = "j76h5PEMx3FIGr3caArJ5g==".getBytes();
        byte[] sep = new byte[]{(byte) '|'};
        OauthProxyTokenSigner s = new OauthProxyTokenSigner(secret, sep);
        String key = "_oauth2_proxy_csrf";
        String value = "hVV2htpqQw4UXgsLYtKdAWct1VAg_yPMxjq2xrGaaCfZStG0p6sGjlAGim1a686QrbBgDGNnpr6LrKH88uTQpTMHLiknn-YbVnXsbFtRyciE5QJIk3q8t24=|1688047283|MFrbdc2q8uQSZd9bpfaWWAmfkHY3U4mijmQo-vqMRKw=";
        Optional<SignedToken> optionalSignedToken = SignedTokenObjectFinder.parseOauthProxySignedToken(key, value);
        if (optionalSignedToken.isPresent()) {
            OauthProxySignedToken token = (OauthProxySignedToken) optionalSignedToken.get();
            token.setSigner(s);
            Assertions.assertDoesNotThrow(() -> {
                s.unsign(String.format("%s|%s", key, value).getBytes());
            });
        } else {
            Assertions.fail("Token not found.");
        }
    }
    @Test
    void OauthProxyBruteForceTest() {
    Assertions.assertDoesNotThrow(() -> {
        String key = "_oauth2_proxy_csrf";
        String value = "hVV2htpqQw4UXgsLYtKdAWct1VAg_yPMxjq2xrGaaCfZStG0p6sGjlAGim1a686QrbBgDGNnpr6LrKH88uTQpTMHLiknn-YbVnXsbFtRyciE5QJIk3q8t24=|1688047283|MFrbdc2q8uQSZd9bpfaWWAmfkHY3U4mijmQo-vqMRKw=";
        Optional<SignedToken> optionalSignedToken = SignedTokenObjectFinder.parseOauthProxySignedToken(key, value);
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
