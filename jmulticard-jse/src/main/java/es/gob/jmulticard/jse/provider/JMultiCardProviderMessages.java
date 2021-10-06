package es.gob.jmulticard.jse.provider;

import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.logging.Logger;

/** Gestor de textos de usuario para las todas las tarjetas del proveedor.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class JMultiCardProviderMessages {

	private static final String BUNDLE_NAME = "jmulticardprovidermessages"; //$NON-NLS-1$

	private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle(BUNDLE_NAME);

	private JMultiCardProviderMessages() {
		// No instanciable
	}

	/** Obtiene el texto relativo a la clave proporcionada.
	 * @param key Clave del texto.
	 * @return Texto. */
	public static String getString(final String key) {
		try {
			return RESOURCE_BUNDLE.getString(key);
		}
		catch (final MissingResourceException e) {
			Logger.getLogger("test.es.gob.jmulticard").severe( //$NON-NLS-1$
				"No se ha encontrado el texto para la clave " + key + " en " + BUNDLE_NAME + ": " + e//$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			);
			return '!' + key + '!';
		}
	}
}
