package io.github.filipopov.keycloak.bcrypt;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Registers the {@code bcrypt} password hashing provider.
 *
 * <p>Configuration (optional): {@code --spi-password-hashing--bcrypt--cost=12}. The cost is only used
 * when Keycloak asks this provider to <em>create</em> a hash, i.e. when a realm's password policy sets
 * {@code hashAlgorithm(bcrypt)}. Verification always uses the cost stored in the hash.
 *
 * <p>{@link #order()} is left at {@code 0}, so this provider never becomes the server-wide default
 * password hashing algorithm by accident.
 */
public final class BCryptPasswordHashProviderFactory implements PasswordHashProviderFactory {

    public static final String ID = "bcrypt";

    public static final String COST_PROPERTY = "cost";

    public static final int DEFAULT_COST = 12;

    private int cost = DEFAULT_COST;

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new BCryptPasswordHashProvider(cost);
    }

    @Override
    public void init(Config.Scope config) {
        cost = BCryptPasswordHashProvider.requireValidCost(config.getInt(COST_PROPERTY, DEFAULT_COST));
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // nothing to do
    }

    @Override
    public void close() {
        // nothing to release
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(COST_PROPERTY)
                .type(ProviderConfigProperty.INTEGER_TYPE)
                .helpText("bcrypt cost factor (4-31) used when hashing new passwords with bcrypt. "
                        + "Verification always uses the cost stored in the hash.")
                .defaultValue(DEFAULT_COST)
                .add()
                .build();
    }
}
