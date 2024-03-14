package one.d4d.dangerous;
import one.d4d.dangerous.keys.SecretKey;
import com.google.common.collect.Lists;
import one.d4d.dangerous.crypto.TokenSigner;
import one.d4d.dangerous.model.SignedToken;
import one.d4d.dangerous.model.UnknownSignedToken;
import one.d4d.dangerous.utils.Utils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;

public class BruteForce {
    private final Set<String> secrets;
    private final Set<String> salts;
    private final List<SecretKey> signingKeys;
    private final Attack scanConfiguration;
    private final SignedToken token;
    private ExecutorService executor;

    public BruteForce(Set<String> secrets,
                      Set<String> salts,
                      List<SecretKey> signingKeys,
                      Attack scanConfiguration,
                      SignedToken token) {
        this.secrets = secrets;
        this.salts = salts;
        this.signingKeys = signingKeys;
        this.scanConfiguration = scanConfiguration;
        this.token = token;
    }

    public List<TokenSigner> prepareAdvanced() {
        List<TokenSigner> attacks = new ArrayList<>();

        List<Derivation> derivations = new ArrayList<>(List.of(Derivation.values()));

        Set<MessageDerivation> messages = new HashSet<>(List.of(MessageDerivation.NONE));

        List<MessageDigestAlgorithm> digests = new ArrayList<>(List.of(MessageDigestAlgorithm.values()));

        TokenSigner is = token.getSigner();
        this.signingKeys.forEach(key -> {
            TokenSigner ks = new TokenSigner(key);
            attacks.add(ks);
        });

        if (scanConfiguration == Attack.KNOWN) return attacks;

        if (scanConfiguration == Attack.FAST) {
            secrets.forEach(secret ->
                    is.getKnownDerivations().forEach(d -> attacks.addAll(is.cloneWithSaltDerivation(secret, salts, d)))
            );
            return attacks;
        }

        if (token instanceof UnknownSignedToken) messages.addAll(List.of(MessageDerivation.values()));

        if (scanConfiguration == Attack.Balanced) derivations.removeIf(
                d -> d == Derivation.PBKDF2HMAC || d == Derivation.RUBY5 || d == Derivation.RUBY5_TRUNCATED);

        secrets.forEach(secret -> {
            messages.forEach(md -> {
                derivations.forEach(d -> {
                    if (d == Derivation.CONCAT || d == Derivation.DJANGO || d == Derivation.HASH) {
                        digests.forEach(mda -> {
                            attacks.addAll(is.cloneWithSaltDerivation(secret, salts, d, md, mda));
                        });
                    } else {
                        attacks.addAll(is.cloneWithSaltDerivation(secret, salts, d, md));
                    }
                });
            });
        });
        return attacks;
    }

    public SecretKey search(List<TokenSigner> attacks) {
        byte[] message = token.getEncodedMessage().getBytes();
        byte[] signature = token.getEncodedSignature().getBytes();
        for (TokenSigner s : attacks) {
            try {
                s.fast_unsign(message, signature);
                return s.getKey();
            } catch (BadSignatureException ignored) {
            }
        }
        return null;
    }

    public SecretKey parallel() {
        int NUMBER_OF_CORES = Runtime.getRuntime().availableProcessors();
        List<TokenSigner> attacks = prepareAdvanced();
        if (NUMBER_OF_CORES < 2) {
            return search(attacks);
        }
        this.executor = Executors.newFixedThreadPool(NUMBER_OF_CORES);
        byte[] message = token.getEncodedMessage().getBytes();
        byte[] signature = token.getEncodedSignature().getBytes();
        List<Callable<SecretKey>> tasks = new ArrayList<>();
//        Lists.partition(attacks, Utils.BRUTE_FORCE_CHUNK_SIZE)
        Lists.partition(attacks, Math.max(1, attacks.size() / NUMBER_OF_CORES))
                .forEach(partition -> {
                    tasks.add(() -> {
                        for (TokenSigner s : partition) {
                            try {
                                s.fast_unsign(message, signature);
                                return s.getKey();
                            } catch (BadSignatureException ignored) {
                            }
                        }
                        throw new RuntimeException("Key not found");
                    });
                });
        try {
            return executor.invokeAny(tasks);
        } catch (InterruptedException | ExecutionException ignored) {
            return null;
        } finally {
            executor.shutdown();
        }
    }

    public void shutdown() {
        if (this.executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(500, TimeUnit.MILLISECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException ignored) {

            }
        }
    }
}
