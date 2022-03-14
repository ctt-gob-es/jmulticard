package es.gob.jmulticard.jse.provider;

import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import es.gob.jmulticard.apdu.connection.ApduConnection;

/** Utilidades comunes a todos los proveedores.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class ProviderUtil {

	private ProviderUtil() {
		// No instanciable
	}

	/** Nombre de la clase por defecto para conexi&oacute;n con las tarjetas. */
	public static final String DEFAULT_PROVIDER_CLASSNAME = "es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection"; //$NON-NLS-1$

    /** Obtiene la conexi&oacute;n por defecto.
     * @return Conexi&oacute;n por defecto ("es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection"). */
    public static ApduConnection getDefaultConnection() {
    	try {
			return (ApduConnection) Class.forName(
					DEFAULT_PROVIDER_CLASSNAME
			).getConstructor().newInstance();
		}
    	catch (InstantiationException    |
    		   IllegalAccessException    |
    		   IllegalArgumentException  |
    		   InvocationTargetException |
    		   NoSuchMethodException     |
    		   SecurityException         |
    		   ClassNotFoundException e) {
			throw new IllegalStateException(
				"No se ha podido instanciar la conexion " + DEFAULT_PROVIDER_CLASSNAME, e //$NON-NLS-1$
			);
		}
    }

    /** Proveedores ligados a dispositivos hardware o bibliotecas externas. */
    private static final List<String> FORBIDDEN_PROVIDERS = Arrays.asList(
		"Ceres430JCAProvider", "SunMSCAPI", "DNIeJCAProvider" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	);

	/** Obtiene el proveedor por defecto para un servicio y un algoritmo dados y
	 * no ligado a un dispositivo hardware o a una biblioteca externa a Java.
	 * @param serviceName Nombre del servicio.
	 * @param serviceAlgorithm Nombre del algoritmo.
	 * @return Proveedor por defecto no ligado a un dispositivo hardware.
	 * @throws NoSuchAlgorithmException Si no se encuentra un proveedor por defecto
	 *         no ligado a un dispositivo hardware para el servicio y el
	 *         algoritmo proporcionados. */
	public static String getDefaultOtherProvider(final String serviceName, final String serviceAlgorithm) throws NoSuchAlgorithmException {
		final Provider[] providerList = Security.getProviders();
		for (final Provider provider : providerList) {
			final Set<Service> serviceList = provider.getServices();
			for (final Service service : serviceList) {
				if (serviceName.equals(service.getType()) && serviceAlgorithm.equals(service.getAlgorithm())) {
					final String providerName = provider.getName();
					if (!FORBIDDEN_PROVIDERS.contains(providerName) && !providerName.contains("PKCS11")) { //$NON-NLS-1$
						return providerName;
					}
				}
			}
		}
		throw new NoSuchAlgorithmException(
			"No hay proveedor adicional para el servicio " + serviceName + " y el algoritmo " + serviceAlgorithm //$NON-NLS-1$ //$NON-NLS-2$
		);
	}

}
