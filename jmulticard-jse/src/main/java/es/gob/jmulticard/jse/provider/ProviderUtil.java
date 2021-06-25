package es.gob.jmulticard.jse.provider;

import java.lang.reflect.InvocationTargetException;

import es.gob.jmulticard.apdu.connection.ApduConnection;

/** Utilidades comunes a todos los proveedores.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class ProviderUtil {

	private ProviderUtil() {
		// No instanciable
	}

    /** Obtiene la conexi&oacute;n por defecto.
     * @return Conexi&oacute;n por defecto ("es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection"). */
    public static ApduConnection getDefaultConnection() {
    	try {
			return (ApduConnection) Class.forName(
				"es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection" //$NON-NLS-1$
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
				"No se ha podido instanciar la conexion 'SmartcardIoConnection': " + e, e //$NON-NLS-1$
			);
		}
    }

}
