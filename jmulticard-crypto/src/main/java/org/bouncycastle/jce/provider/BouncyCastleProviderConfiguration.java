package org.bouncycastle.jce.provider;

import java.security.Permission;
import java.security.spec.DSAParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jcajce.provider.config.ProviderConfigurationPermission;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

class BouncyCastleProviderConfiguration implements ProviderConfiguration {

    private static Permission BC_EC_LOCAL_PERMISSION = new ProviderConfigurationPermission(
        BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider.THREAD_LOCAL_EC_IMPLICITLY_CA);
    private static Permission BC_EC_PERMISSION = new ProviderConfigurationPermission(
        BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider.EC_IMPLICITLY_CA);
    private static Permission BC_DH_LOCAL_PERMISSION = new ProviderConfigurationPermission(
        BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS);
    private static Permission BC_DH_PERMISSION = new ProviderConfigurationPermission(
        BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider.DH_DEFAULT_PARAMS);
    private static Permission BC_EC_CURVE_PERMISSION = new ProviderConfigurationPermission(
        BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider.ACCEPTABLE_EC_CURVES);
    private static Permission BC_ADDITIONAL_EC_CURVE_PERMISSION = new ProviderConfigurationPermission(
        BouncyCastleProvider.PROVIDER_NAME, ConfigurableProvider.ADDITIONAL_EC_PARAMETERS);

    private final ThreadLocal ecThreadSpec = new ThreadLocal();
    private final ThreadLocal dhThreadSpec = new ThreadLocal();

    private volatile ECParameterSpec ecImplicitCaParams;
    private volatile Object dhDefaultParams;
    private volatile Set acceptableNamedCurves = new HashSet();
    private volatile Map additionalECParameters = new HashMap();

    void setParameter(final String parameterName, final Object parameter)
    {
        final SecurityManager securityManager = System.getSecurityManager();

        if (ConfigurableProvider.THREAD_LOCAL_EC_IMPLICITLY_CA.equals(parameterName))
        {
            ECParameterSpec curveSpec;

            if (securityManager != null)
            {
                securityManager.checkPermission(BC_EC_LOCAL_PERMISSION);
            }

            if (parameter instanceof ECParameterSpec || parameter == null)
            {
                curveSpec = (ECParameterSpec)parameter;
            }
            else  // assume java.security.spec
            {
                curveSpec = EC5Util.convertSpec((java.security.spec.ECParameterSpec)parameter);
            }

            if (curveSpec == null)
            {
                ecThreadSpec.remove();
            }
            else
            {
                ecThreadSpec.set(curveSpec);
            }
        }
        else if (ConfigurableProvider.EC_IMPLICITLY_CA.equals(parameterName))
        {
            if (securityManager != null)
            {
                securityManager.checkPermission(BC_EC_PERMISSION);
            }

            if (parameter instanceof ECParameterSpec || parameter == null)
            {
                ecImplicitCaParams = (ECParameterSpec)parameter;
            }
            else  // assume java.security.spec
            {
                ecImplicitCaParams = EC5Util.convertSpec((java.security.spec.ECParameterSpec)parameter);
            }
        }
        else if (ConfigurableProvider.THREAD_LOCAL_DH_DEFAULT_PARAMS.equals(parameterName))
        {
            Object dhSpec;

            if (securityManager != null)
            {
                securityManager.checkPermission(BC_DH_LOCAL_PERMISSION);
            }

            if (parameter instanceof DHParameterSpec || parameter instanceof DHParameterSpec[] || parameter == null)
            {
                dhSpec = parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid DHParameterSpec");
            }

            if (dhSpec == null)
            {
                dhThreadSpec.remove();
            }
            else
            {
                dhThreadSpec.set(dhSpec);
            }
        }
        else if (ConfigurableProvider.DH_DEFAULT_PARAMS.equals(parameterName))
        {
            if (securityManager != null)
            {
                securityManager.checkPermission(BC_DH_PERMISSION);
            }

            if (parameter instanceof DHParameterSpec || parameter instanceof DHParameterSpec[] || parameter == null)
            {
                dhDefaultParams = parameter;
            }
            else
            {
                throw new IllegalArgumentException("not a valid DHParameterSpec or DHParameterSpec[]");
            }
        }
        else if (ConfigurableProvider.ACCEPTABLE_EC_CURVES.equals(parameterName))
        {
            if (securityManager != null)
            {
                securityManager.checkPermission(BC_EC_CURVE_PERMISSION);
            }

            acceptableNamedCurves = (Set)parameter;
        }
        else if (ConfigurableProvider.ADDITIONAL_EC_PARAMETERS.equals(parameterName))
        {
            if (securityManager != null)
            {
                securityManager.checkPermission(BC_ADDITIONAL_EC_CURVE_PERMISSION);
            }

            additionalECParameters = (Map)parameter;
        }
    }

    @Override
	public ECParameterSpec getEcImplicitlyCa()
    {
        final ECParameterSpec spec = (ECParameterSpec)ecThreadSpec.get();

        if (spec != null)
        {
            return spec;
        }

        return ecImplicitCaParams;
    }

    @Override
	public DHParameterSpec getDHDefaultParameters(final int keySize)
    {
        Object params = dhThreadSpec.get();
        if (params == null)
        {
            params = dhDefaultParams;
        }

        if (params instanceof DHParameterSpec)
        {
            final DHParameterSpec spec = (DHParameterSpec)params;

            if (spec.getP().bitLength() == keySize)
            {
                return spec;
            }
        }
        else if (params instanceof DHParameterSpec[])
        {
            final DHParameterSpec[] specs = (DHParameterSpec[])params;

            for (final DHParameterSpec spec : specs) {
                if (spec.getP().bitLength() == keySize)
                {
                    return spec;
                }
            }
        }

        final DHParameters dhParams = CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DH_DEFAULT_PARAMS, keySize);
        if (dhParams != null)
        {
            return new DHDomainParameterSpec(dhParams);
        }

        return null;
    }

    @Override
	public DSAParameterSpec getDSADefaultParameters(final int keySize)
    {
        final DSAParameters dsaParams = CryptoServicesRegistrar.getSizedProperty(CryptoServicesRegistrar.Property.DSA_DEFAULT_PARAMS, keySize);
        if (dsaParams != null)
        {
            return new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
        }

        return null;
    }

    @Override
	public Set getAcceptableNamedCurves()
    {
        return Collections.unmodifiableSet(acceptableNamedCurves);
    }

    @Override
	public Map getAdditionalECParameters()
    {
        return Collections.unmodifiableMap(additionalECParameters);
    }
}
