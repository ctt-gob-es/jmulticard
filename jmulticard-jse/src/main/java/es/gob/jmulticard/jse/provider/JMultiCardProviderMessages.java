package es.gob.jmulticard.jse.provider;

import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Gestor de textos de usuario para las todas las tarjetas del proveedor.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class JMultiCardProviderMessages {

	private static final Logger LOGGER = Logger.getLogger(JMultiCardProviderMessages.class.getName());

	private static final String BUNDLE_NAME = "jmulticardprovidermessages"; //$NON-NLS-1$

	private static ResourceBundle resourceBundle;
	static {
		try {
			resourceBundle = ResourceBundle.getBundle(BUNDLE_NAME);
		}
		catch(final Exception e) {
			LOGGER.log(Level.SEVERE, "No se han podido cargar los textos de '" + BUNDLE_NAME + "'", e); //$NON-NLS-1$ //$NON-NLS-2$
			resourceBundle = null;
		}
	}

	private JMultiCardProviderMessages() {
		// No instanciable
	}

	/** Obtiene el texto relativo a la clave proporcionada.
	 * @param key Clave del texto.
	 * @return Texto. */
	public static String getString(final String key) {
		try {
			return resourceBundle.getString(key);
		}
		catch (final NullPointerException | MissingResourceException | ClassCastException  e) {
			LOGGER.severe(
				"No se ha encontrado el texto para la clave " + key + " en " + BUNDLE_NAME + ": " + e//$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			);
			return '!' + key + '!';
		}
	}
}
