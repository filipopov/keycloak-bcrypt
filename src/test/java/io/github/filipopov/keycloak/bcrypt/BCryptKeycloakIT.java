package io.github.filipopov.keycloak.bcrypt;

import static org.assertj.core.api.Assertions.assertThat;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.CredentialRepresentation;

/**
 * Starts a real Keycloak with the shaded provider jar and the realm from {@code examples/realm-import.json}.
 *
 * <p>Requires Docker. Not part of the default build; run with {@code ./mvnw -B verify -Pit}.
 */
class BCryptKeycloakIT {

    private static final String REALM = "appointiko";
    private static final String CLIENT_ID = "appointiko-cli";

    private static KeycloakContainer keycloak;
    private static Keycloak admin;

    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    static void startKeycloak() {
        keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version"))
                .withProviderLibsFrom(List.of(new File(System.getProperty("provider.jar"))))
                .withRealmImportFile("realm-import.json");
        keycloak.start();
        admin = keycloak.getKeycloakAdminClient();
    }

    @AfterAll
    static void stopKeycloak() {
        if (admin != null) {
            admin.close();
        }
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    @Test
    void rejectsWrongPassword() throws Exception {
        assertThat(passwordGrant("jane", "wrong-password")).isEqualTo(401);
    }

    @Test
    void springStyleHashLogsInAndIsRehashedToRealmDefault() throws Exception {
        assertThat(passwordAlgorithm("jane")).isEqualTo("bcrypt");

        assertThat(passwordGrant("jane", "change-me-please")).isEqualTo(200);

        assertThat(awaitPasswordAlgorithmOtherThan("jane", "bcrypt")).isEqualTo("argon2");
        assertThat(passwordGrant("jane", "change-me-please")).isEqualTo(200);
        assertThat(passwordGrant("jane", "wrong-password")).isEqualTo(401);
    }

    @Test
    void phpStyleHashLogsIn() throws Exception {
        assertThat(passwordGrant("php-user", "appointiko")).isEqualTo(200);
    }

    private int passwordGrant(String username, String password) throws IOException, InterruptedException {
        String form = Map.of(
                        "grant_type", "password",
                        "client_id", CLIENT_ID,
                        "username", username,
                        "password", password)
                .entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest request = HttpRequest.newBuilder(URI.create(keycloak.getTokenEndpoint(REALM)))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    /** Keycloak re-hashes in a separate transaction after the login completes, so poll briefly. */
    private String awaitPasswordAlgorithmOtherThan(String username, String algorithm) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        String current = passwordAlgorithm(username);
        while (algorithm.equals(current) && System.nanoTime() < deadline) {
            Thread.sleep(200);
            current = passwordAlgorithm(username);
        }
        return current;
    }

    private String passwordAlgorithm(String username) {
        var users = admin.realm(REALM).users();
        UserResource user = users.get(users.searchByUsername(username, true).getFirst().getId());
        CredentialRepresentation password = user.credentials().stream()
                .filter(c -> CredentialRepresentation.PASSWORD.equals(c.getType()))
                .findFirst()
                .orElseThrow();
        // credentialData is returned to admins, secretData is not
        String credentialData = password.getCredentialData();
        int start = credentialData.indexOf("\"algorithm\":\"") + "\"algorithm\":\"".length();
        return credentialData.substring(start, credentialData.indexOf('"', start));
    }
}
