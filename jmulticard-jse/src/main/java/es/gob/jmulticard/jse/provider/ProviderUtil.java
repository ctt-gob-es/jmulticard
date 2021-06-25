package es.gob.jmulticard.jse.provider;

import java.lang.reflect.InvocationTargetException;

import es.gob.jmulticard.apdu.connection.ApduConnection;

/** Utilidades comunes a todos los proveedores.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class ProviderUtil {

	private ProviderUtil() {
		// No instanciable
	}

	static final String DEFAULT_PROVIDER_CLASSNAME = "es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection"; //$NON-NLS-1$

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
				"No se ha podido instanciar la conexion '" + DEFAULT_PROVIDER_CLASSNAME + "': " + e, e //$NON-NLS-1$ //$NON-NLS-2$
			);
		}
    }

}
