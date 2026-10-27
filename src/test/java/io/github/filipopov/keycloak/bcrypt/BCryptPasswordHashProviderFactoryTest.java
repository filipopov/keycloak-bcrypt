package io.github.filipopov.keycloak.bcrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

class BCryptPasswordHashProviderFactoryTest {

    @Test
    void hasIdBcrypt() {
        assertThat(new BCryptPasswordHashProviderFactory().getId()).isEqualTo("bcrypt");
    }

    @Test
    void isRegisteredForServiceLoader() {
        assertThat(ServiceLoader.load(PasswordHashProviderFactory.class))
                .map(Object::getClass)
                .contains(BCryptPasswordHashProviderFactory.class);
    }

    @Test
    void neverBecomesTheDefaultHashProviderByOrder() {
        // Keycloak only auto-selects a default provider among factories with order() > 0
        assertThat(new BCryptPasswordHashProviderFactory().order()).isZero();
    }

    @Test
    void usesCost12ByDefault() {
        BCryptPasswordHashProviderFactory factory = new BCryptPasswordHashProviderFactory();
        factory.init(new MapScope(Map.of()));

        assertThat(((BCryptPasswordHashProvider) factory.create(null)).defaultCost()).isEqualTo(12);
    }

    @Test
    void readsCostFromConfig() {
        BCryptPasswordHashProviderFactory factory = new BCryptPasswordHashProviderFactory();
        factory.init(new MapScope(Map.of("cost", "10")));

        assertThat(((BCryptPasswordHashProvider) factory.create(null)).defaultCost()).isEqualTo(10);
    }

    @Test
    void failsFastOnInvalidCost() {
        BCryptPasswordHashProviderFactory factory = new BCryptPasswordHashProviderFactory();

        assertThatThrownBy(() -> factory.init(new MapScope(Map.of("cost", "32"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("between 4 and 31");
    }

    @Test
    void describesCostOption() {
        assertThat(new BCryptPasswordHashProviderFactory().getConfigMetadata())
                .singleElement()
                .satisfies(property -> {
                    assertThat(property.getName()).isEqualTo("cost");
                    assertThat(property.getType()).isEqualTo(ProviderConfigProperty.INTEGER_TYPE);
                    assertThat(property.getDefaultValue()).isEqualTo(12);
                });
    }

    /** Minimal in-memory {@link Config.Scope}. */
    private static final class MapScope extends Config.AbstractScope {

        private final Map<String, String> values;

        MapScope(Map<String, String> values) {
            this.values = values;
        }

        @Override
        public String get(String key) {
            return values.get(key);
        }

        @Override
        public Config.Scope scope(String... scope) {
            return new MapScope(Map.of());
        }

        @Override
        public Set<String> getPropertyNames() {
            return values.keySet();
        }

        @Override
        public Config.Scope root() {
            return this;
        }
    }
}
