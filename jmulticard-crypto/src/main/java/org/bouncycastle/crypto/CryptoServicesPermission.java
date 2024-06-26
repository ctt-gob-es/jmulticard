package org.bouncycastle.crypto;

import java.security.Permission;
import java.util.HashSet;
import java.util.Set;

/**
 * Permissions that need to be configured if a SecurityManager is used.
 */
public class CryptoServicesPermission
    extends Permission
{
    /**
     * Enable the setting of global configuration properties. This permission implies THREAD_LOCAL_CONFIG
     */
    public static final String GLOBAL_CONFIG = "globalConfig";

    /**
     * Enable the setting of thread local configuration properties.
     */
    public static final String THREAD_LOCAL_CONFIG = "threadLocalConfig";

    /**
     * Enable the setting of the default SecureRandom.
     */
    public static final String DEFAULT_RANDOM = "defaultRandomConfig";

    /**
     * Enable the setting of the constraints.
     */
    public static final String CONSTRAINTS = "constraints";

    private final Set<String> actions = new HashSet<>();

    public CryptoServicesPermission(final String name)
    {
        super(name);

        actions.add(name);
    }

    @Override
	public boolean implies(final Permission permission)
    {
        if (permission instanceof CryptoServicesPermission)
        {
            final CryptoServicesPermission other = (CryptoServicesPermission)permission;

            if (this.getName().equals(other.getName()) || actions.containsAll(other.actions))
            {
                return true;
            }
        }

        return false;
    }

    @Override
	public boolean equals(final Object obj)
    {
        if (obj instanceof CryptoServicesPermission)
        {
            final CryptoServicesPermission other = (CryptoServicesPermission)obj;

            if (actions.equals(other.actions))
            {
                return true;
            }
        }

        return false;
    }

    @Override
	public int hashCode()
    {
        return actions.hashCode();
    }

    @Override
	public String getActions()
    {
        return actions.toString();
    }
}
