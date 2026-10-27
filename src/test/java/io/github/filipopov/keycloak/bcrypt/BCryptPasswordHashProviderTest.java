package io.github.filipopov.keycloak.bcrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordCredentialData;
import org.keycloak.policy.PasswordPolicyProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class BCryptPasswordHashProviderTest {

    private final BCryptPasswordHashProvider provider = new BCryptPasswordHashProvider(BCryptPasswordHashProviderFactory.DEFAULT_COST);

    /** Same shape Keycloak builds from imported {@code credentialData} / {@code secretData}. */
    private static PasswordCredentialModel imported(String hash) {
        return PasswordCredentialModel.createFromValues("bcrypt", new byte[0], -1, hash);
    }

    /**
     * Builds a realm policy {@code hashIterations(n)} with a minimal fake session that only knows the
     * integer-valued policy provider Keycloak uses for this setting.
     */
    private static PasswordPolicy hashIterations(int iterations) {
        PasswordPolicyProvider integerPolicy = (PasswordPolicyProvider) Proxy.newProxyInstance(
                PasswordPolicyProvider.class.getClassLoader(), new Class<?>[] {PasswordPolicyProvider.class},
                (proxy, method, args) -> "parseConfig".equals(method.getName()) ? Integer.valueOf((String) args[0]) : null);
        KeycloakSession session = (KeycloakSession) Proxy.newProxyInstance(
                KeycloakSession.class.getClassLoader(), new Class<?>[] {KeycloakSession.class},
                (proxy, method, args) -> "getProvider".equals(method.getName()) ? integerPolicy : null);
        return PasswordPolicy.parse(session, "hashIterations(" + iterations + ")");
    }

    @Nested
    class Verify {

        @ParameterizedTest(name = "Spring BCryptPasswordEncoder, cost {0}")
        @ValueSource(ints = {4, 8, 10, 12})
        void acceptsSpringSecurityHashes(int cost) {
            String hash = new BCryptPasswordEncoder(cost).encode("appointiko-secret");

            assertThat(hash).startsWith("$2a$%02d$".formatted(cost));
            assertThat(provider.verify("appointiko-secret", imported(hash))).isTrue();
            assertThat(provider.verify("appointiko-Secret", imported(hash))).isFalse();
        }

        @ParameterizedTest(name = "Spring BCryptPasswordEncoder, version {0}")
        @CsvSource({"$2A, $2a$", "$2B, $2b$", "$2Y, $2y$"})
        void acceptsAllSpringSecurityVersions(BCryptPasswordEncoder.BCryptVersion version, String prefix) {
            String hash = new BCryptPasswordEncoder(version, 6).encode("pässwörd");

            assertThat(hash).startsWith(prefix);
            assertThat(provider.verify("pässwörd", imported(hash))).isTrue();
            assertThat(provider.verify("passwort", imported(hash))).isFalse();
        }

        @ParameterizedTest(name = "PHP / Apache $2y$ hash: {1}")
        @CsvSource(delimiter = '|', value = {
                // example from the PHP manual (password_verify)
                "rasmuslerdorf                | $2y$07$BCryptRequires22Chrcte/VlQH0piJtjXl.0t1XkA8pw9dMXTpOq",
                // generated with: htpasswd -nbB -C <cost> u '<password>'
                "correct horse battery staple | $2y$04$.WA2hOcVSLULTPPLad3woOXCx0CFEOdYLVnmlZH1drLX70v.5pJ2a",
                "S3cr3t!-ünïcødé              | $2y$10$IMtFijydewEXBvntu52xD.MUdUZPvS1rtW2T9nS8g4za.o49SqMQS",
                "appointiko                   | $2y$12$pGebS3.juJHxuWbWVq32O.SM7oavbplMNFxFor0h5.XtbzPBzAEvG"
        })
        void acceptsPhpStyleHashes(String password, String hash) {
            assertThat(provider.verify(password, imported(hash))).isTrue();
            assertThat(provider.verify(password + "x", imported(hash))).isFalse();
        }

        @Test
        void hashesCreatedByThisProviderVerifyWithSpringSecurity() {
            PasswordCredentialModel credential = provider.encodedCredential("round-trip", 4);

            assertThat(new BCryptPasswordEncoder().matches("round-trip", credential.getPasswordSecretData().getValue()))
                    .isTrue();
        }

        @Test
        void rejectsWrongEmptyAndNullPasswords() {
            PasswordCredentialModel credential = imported(new BCryptPasswordEncoder(4).encode("secret"));

            assertThat(provider.verify("wrong", credential)).isFalse();
            assertThat(provider.verify("", credential)).isFalse();
            assertThat(provider.verify(null, credential)).isFalse();
        }

        @Test
        void truncatesPasswordsLongerThan72BytesLikeStandardBcrypt() {
            String first72 = "a".repeat(72);
            PasswordCredentialModel credential = imported(new BCryptPasswordEncoder(4).encode(first72));

            assertThat(first72.getBytes(StandardCharsets.UTF_8)).hasSize(72);
            assertThat(provider.verify(first72 + "anything-after-byte-72", credential)).isTrue();
            assertThat(provider.verify("a".repeat(71), credential)).isFalse();
        }

        @ParameterizedTest(name = "malformed: \"{0}\"")
        @ValueSource(strings = {
                "",
                "not-a-hash",
                // $2x$ (crypt_blowfish bug-compat) and $2$ are deliberately not supported
                "$2x$04$.WA2hOcVSLULTPPLad3woOXCx0CFEOdYLVnmlZH1drLX70v.5pJ2a",
                "$2$04$.WA2hOcVSLULTPPLad3woOXCx0CFEOdYLVnmlZH1drLX70v.5pJ2a",
                // truncated
                "$2y$04$.WA2hOcVSLULTPPLad3woOXCx0CFEOdYLVnmlZH1drLX70v.5pJ2",
                // cost out of range
                "$2y$99$.WA2hOcVSLULTPPLad3woOXCx0CFEOdYLVnmlZH1drLX70v.5pJ2a",
                "$2y$03$.WA2hOcVSLULTPPLad3woOXCx0CFEOdYLVnmlZH1drLX70v.5pJ2a",
                // invalid radix64 character
                "$2y$04$.WA2hOcVSLULTPPLad3woOXCx0CFEOdYLVnmlZH1drLX70v.5pJ2!",
                // a PBKDF2 value
                "Lk4bMyaWnQNR7OXIkHXgLq2fTvTQR4z0Klpq9vCZdq8="
        })
        void returnsFalseForMalformedHashes(String hash) {
            assertThat(provider.verify("correct horse battery staple", imported(hash))).isFalse();
        }

        @Test
        void returnsFalseWhenSecretIsMissing() {
            PasswordCredentialModel credential =
                    PasswordCredentialModel.createFromValues(new PasswordCredentialData(-1, "bcrypt"), null);

            assertThat(provider.verify("secret", credential)).isFalse();
        }
    }

    @Nested
    class EncodedCredential {

        @Test
        void usesConfiguredDefaultCostWhenRealmDoesNotSetIterations() {
            PasswordCredentialModel credential = new BCryptPasswordHashProvider(5).encodedCredential("secret", -1);

            assertThat(credential.getType()).isEqualTo(PasswordCredentialModel.TYPE);
            assertThat(credential.getPasswordCredentialData().getAlgorithm()).isEqualTo("bcrypt");
            assertThat(credential.getPasswordCredentialData().getHashIterations()).isEqualTo(5);
            assertThat(credential.getPasswordSecretData().getValue()).matches("^\\$2a\\$05\\$[./A-Za-z0-9]{53}$");
        }

        @Test
        void usesRealmHashIterationsAsCostWhenInBcryptRange() {
            PasswordCredentialModel credential = provider.encodedCredential("secret", 6);

            assertThat(credential.getPasswordSecretData().getValue()).startsWith("$2a$06$");
            assertThat(provider.verify("secret", credential)).isTrue();
        }

        @Test
        void fallsBackToDefaultCostForPbkdf2StyleIterationCounts() {
            PasswordCredentialModel credential = new BCryptPasswordHashProvider(4).encodedCredential("secret", 27500);

            assertThat(credential.getPasswordSecretData().getValue()).startsWith("$2a$04$");
        }

        @Test
        void producesSaltedHashes() {
            String first = provider.encodedCredential("secret", 4).getPasswordSecretData().getValue();
            String second = provider.encodedCredential("secret", 4).getPasswordSecretData().getValue();

            assertThat(first).isNotEqualTo(second);
        }

        @Test
        void rejectsPasswordsLongerThan72BytesInsteadOfTruncating() {
            assertThatThrownBy(() -> provider.encodedCredential("a".repeat(73), 4))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void exposesCostAsHashingStrength() {
            assertThat(provider.credentialHashingStrength(provider.encodedCredential("secret", 4))).isEqualTo("cost=4");
            assertThat(provider.credentialHashingStrength(imported("garbage"))).isEqualTo("unknown");
        }
    }

    @Nested
    class PolicyCheck {

        @Test
        void bcryptHashWithConfiguredCostSatisfiesPolicy() {
            BCryptPasswordHashProvider cost4 = new BCryptPasswordHashProvider(4);

            assertThat(cost4.policyCheck(null, cost4.encodedCredential("secret", -1))).isTrue();
            assertThat(cost4.policyCheck(PasswordPolicy.empty(), cost4.encodedCredential("secret", -1))).isTrue();
        }

        @Test
        void importedHashWithDifferentCostDoesNotSatisfyPolicy() {
            PasswordCredentialModel credential = imported(new BCryptPasswordEncoder(4).encode("secret"));

            assertThat(provider.policyCheck(null, credential)).isFalse();
        }

        @Test
        void realmHashIterationsOverrideDefaultCost() {
            PasswordCredentialModel cost6 = provider.encodedCredential("secret", 6);

            assertThat(provider.policyCheck(hashIterations(6), cost6)).isTrue();
            assertThat(provider.policyCheck(hashIterations(7), cost6)).isFalse();
        }

        @Test
        void nonBcryptCredentialDoesNotSatisfyPolicy() {
            PasswordCredentialModel pbkdf2 = PasswordCredentialModel.createFromValues(
                    "pbkdf2-sha512", new byte[16], 210_000, "Lk4bMyaWnQNR7OXIkHXgLq2fTvTQR4z0Klpq9vCZdq8=");

            assertThat(provider.policyCheck(null, pbkdf2)).isFalse();
        }

        @Test
        void malformedBcryptCredentialDoesNotSatisfyPolicy() {
            assertThat(provider.policyCheck(null, imported("garbage"))).isFalse();
        }
    }

    @Test
    void rejectsInvalidDefaultCost() {
        assertThatThrownBy(() -> new BCryptPasswordHashProvider(3)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BCryptPasswordHashProvider(32)).isInstanceOf(IllegalArgumentException.class);
    }
}
