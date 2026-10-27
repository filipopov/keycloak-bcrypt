package io.github.filipopov.keycloak.bcrypt;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.LongPasswordStrategies;
import java.security.SecureRandom;
import java.util.OptionalInt;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordCredentialData;
import org.keycloak.models.credential.dto.PasswordSecretData;

/**
 * Keycloak {@link PasswordHashProvider} for bcrypt.
 *
 * <p>Its main purpose is to <em>verify</em> bcrypt hashes of users imported from another system
 * ({@code $2a$}, {@code $2b$} and {@code $2y$}, any cost factor). The cost factor and salt are read
 * from the stored hash itself, so the {@code hashIterations} value in the credential data is ignored
 * during verification.
 *
 * <p>Re-hashing to the realm's default algorithm happens in Keycloak itself: after a successful
 * login Keycloak asks the realm's <em>configured</em> hash provider (argon2 / pbkdf2 by default)
 * whether the stored credential matches its policy. For a bcrypt credential that answer is always
 * "no", so Keycloak re-hashes the password with the default algorithm.
 *
 * <p>{@link #encodedCredential(String, int)} produces {@code $2a$} hashes and is only used when a
 * realm explicitly sets {@code hashAlgorithm(bcrypt)} in its password policy.
 */
public final class BCryptPasswordHashProvider implements PasswordHashProvider {

    private static final Logger LOG = Logger.getLogger(BCryptPasswordHashProvider.class);

    /** {@code $2a$}, {@code $2b$} or {@code $2y$}, two-digit cost, 22 chars salt + 31 chars hash. */
    private static final Pattern BCRYPT_HASH = Pattern.compile("^\\$2[aby]\\$(\\d{2})\\$[./A-Za-z0-9]{53}$");

    private static final BCrypt.Version HASH_VERSION = BCrypt.Version.VERSION_2A;

    /** Rejects passwords longer than 72 bytes instead of silently truncating them when hashing. */
    private static final BCrypt.Hasher HASHER =
            BCrypt.with(HASH_VERSION, new SecureRandom(), LongPasswordStrategies.strict(HASH_VERSION));

    /**
     * Version is taken from the hash. Passwords longer than 72 bytes are truncated, which is what
     * standard bcrypt implementations (OpenBSD, PHP, Spring Security &lt; 6.3) did when the hash was created.
     */
    private static final BCrypt.Verifyer VERIFYER =
            BCrypt.verifyer(null, LongPasswordStrategies.truncate(HASH_VERSION));

    private final int defaultCost;

    public BCryptPasswordHashProvider(int defaultCost) {
        this.defaultCost = requireValidCost(defaultCost);
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        PasswordCredentialData data = credential.getPasswordCredentialData();
        if (data == null || !BCryptPasswordHashProviderFactory.ID.equals(data.getAlgorithm())) {
            return false;
        }
        int expectedCost = resolveCost(policy != null ? policy.getHashIterations() : -1);
        OptionalInt actualCost = cost(hashOf(credential));
        return actualCost.isPresent() && actualCost.getAsInt() == expectedCost;
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        int cost = resolveCost(iterations);
        String hash = HASHER.hashToString(cost, rawPassword.toCharArray());
        return PasswordCredentialModel.createFromValues(BCryptPasswordHashProviderFactory.ID, new byte[0], cost, hash);
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        if (rawPassword == null) {
            return false;
        }
        String hash = hashOf(credential);
        if (hash == null || !BCRYPT_HASH.matcher(hash).matches()) {
            LOG.debug("Stored credential is not a supported bcrypt hash ($2a$, $2b$, $2y$)");
            return false;
        }
        BCrypt.Result result;
        try {
            result = VERIFYER.verify(rawPassword.toCharArray(), hash.toCharArray());
        } catch (IllegalArgumentException e) {
            // e.g. a cost factor outside 4-31: treat as a non-matching credential instead of failing the login flow
            LOG.debugf("Stored bcrypt hash rejected: %s", e.getMessage());
            return false;
        }
        if (!result.validFormat) {
            LOG.debugf("Stored bcrypt hash could not be parsed: %s", result.formatErrorMessage);
            return false;
        }
        return result.verified;
    }

    @Override
    public String credentialHashingStrength(PasswordCredentialModel credential) {
        OptionalInt cost = cost(hashOf(credential));
        return cost.isPresent() ? "cost=" + cost.getAsInt() : "unknown";
    }

    @Override
    public void close() {
        // stateless
    }

    int defaultCost() {
        return defaultCost;
    }

    /**
     * Maps Keycloak's {@code hashIterations} to a bcrypt cost: {@code -1} (not set in the realm policy)
     * means the configured default; a value in the valid bcrypt range is used as the cost; anything else
     * (e.g. a PBKDF2-style iteration count) falls back to the default.
     */
    private int resolveCost(int iterations) {
        if (iterations == -1) {
            return defaultCost;
        }
        if (iterations >= BCrypt.MIN_COST && iterations <= BCrypt.MAX_COST) {
            return iterations;
        }
        LOG.warnf("hashIterations=%d is not a valid bcrypt cost (%d-%d); using cost %d",
                iterations, BCrypt.MIN_COST, BCrypt.MAX_COST, defaultCost);
        return defaultCost;
    }

    static int requireValidCost(int cost) {
        if (cost < BCrypt.MIN_COST || cost > BCrypt.MAX_COST) {
            throw new IllegalArgumentException(
                    "bcrypt cost must be between " + BCrypt.MIN_COST + " and " + BCrypt.MAX_COST + ", was " + cost);
        }
        return cost;
    }

    private static String hashOf(PasswordCredentialModel credential) {
        PasswordSecretData secret = credential.getPasswordSecretData();
        return secret != null ? secret.getValue() : null;
    }

    private static OptionalInt cost(String hash) {
        if (hash == null) {
            return OptionalInt.empty();
        }
        Matcher matcher = BCRYPT_HASH.matcher(hash);
        return matcher.matches() ? OptionalInt.of(Integer.parseInt(matcher.group(1))) : OptionalInt.empty();
    }
}
