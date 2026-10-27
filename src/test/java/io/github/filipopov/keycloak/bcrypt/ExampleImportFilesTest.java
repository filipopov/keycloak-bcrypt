package io.github.filipopov.keycloak.bcrypt;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * Feeds the JSON files in {@code examples/} through the same deserialization and conversion code
 * Keycloak uses on import, then verifies the documented passwords against the resulting credential.
 */
class ExampleImportFilesTest {

    private static final Map<String, String> PASSWORDS = Map.of(
            "jane", "change-me-please",
            "php-user", "appointiko");

    private final BCryptPasswordHashProvider provider = new BCryptPasswordHashProvider(BCryptPasswordHashProviderFactory.DEFAULT_COST);

    @Test
    void realmImportUsersCanLogIn() throws IOException {
        RealmRepresentation realm = read("realm-import.json", RealmRepresentation.class);

        assertThat(realm.getUsers()).extracting(UserRepresentation::getUsername).containsExactlyInAnyOrder("jane", "php-user");
        for (UserRepresentation user : realm.getUsers()) {
            assertCredentialVerifies(user, PASSWORDS.get(user.getUsername()));
        }
    }

    @Test
    void adminApiUserPayloadCanLogIn() throws IOException {
        assertCredentialVerifies(read("create-user.json", UserRepresentation.class), "change-me-please");
    }

    private void assertCredentialVerifies(UserRepresentation user, String password) {
        assertThat(user.getCredentials()).hasSize(1);
        CredentialRepresentation representation = user.getCredentials().getFirst();

        PasswordCredentialModel credential =
                PasswordCredentialModel.createFromCredentialModel(RepresentationToModel.toModel(representation));

        assertThat(credential.getType()).isEqualTo(PasswordCredentialModel.TYPE);
        assertThat(credential.getPasswordCredentialData().getAlgorithm()).isEqualTo(BCryptPasswordHashProviderFactory.ID);
        assertThat(provider.verify(password, credential)).as("password of %s", user.getUsername()).isTrue();
        assertThat(provider.verify(password + "!", credential)).isFalse();
    }

    private static <T> T read(String file, Class<T> type) throws IOException {
        try (InputStream in = Files.newInputStream(Path.of("examples", file))) {
            return JsonSerialization.readValue(in, type);
        }
    }
}
