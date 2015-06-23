package es.gob.jmulticard.jse.provider.ceres;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

final class CeresMessages {
	private static final String BUNDLE_NAME = "es.gob.jmulticard.jse.provider.ceres.ceresmessages"; //$NON-NLS-1$

	private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle
			.getBundle(BUNDLE_NAME);

	private CeresMessages() {
	}

	static String getString(final String key) {
		try {
			return RESOURCE_BUNDLE.getString(key);
		}
		catch (final MissingResourceException e) {
			return '!' + key + '!';
		}
	}
}
