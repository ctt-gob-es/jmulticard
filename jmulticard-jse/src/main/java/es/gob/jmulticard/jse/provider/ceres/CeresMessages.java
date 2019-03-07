package es.gob.jmulticard.jse.provider.ceres;

import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.logging.Logger;

final class CeresMessages {

	private static final String BUNDLE_NAME = "es.gob.jmulticard.jse.provider.ceres.ceresmessages"; //$NON-NLS-1$

	private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle(BUNDLE_NAME);

	private CeresMessages() {
		// Vacio
	}

	static String getString(final String key) {
		try {
			return RESOURCE_BUNDLE.getString(key);
		}
		catch (final MissingResourceException e) {
        	Logger.getLogger("es.gob.jmulticard").severe( //$NON-NLS-1$
    			"No se ha encontrado el recurso textual con clave '" + key + "': " + e//$NON-NLS-1$ //$NON-NLS-2$
			);
			return '!' + key + '!';
		}
	}
}
