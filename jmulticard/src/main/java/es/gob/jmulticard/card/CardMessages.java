package es.gob.jmulticard.card;

import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.logging.Level;

import es.gob.jmulticard.JmcLogger;

/** Gestor de mensajes de las tarjetas (principalmente <code>Callbacks</code>).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CardMessages {

	private static final String BUNDLE_NAME = "cardmessages"; //$NON-NLS-1$

	private static ResourceBundle resourceBundle;
	static {
		try {
			resourceBundle = ResourceBundle.getBundle(BUNDLE_NAME);
		}
		catch(final Exception e) {
			JmcLogger.log(
				CardMessages.class.getName(),
				"static", //$NON-NLS-1$
				Level.SEVERE,
				"No se han podido cargar los textos de '" + BUNDLE_NAME + "'", //$NON-NLS-1$ //$NON-NLS-2$
				e
			);
			resourceBundle = null;
		}
	}

	/** Constructor privado y vac&iacute;o. */
	private CardMessages() {
		// No instanciable
	}

    /** Recupera el texto identificado con la clave proporcionada y sustituye la
     * subcadena "%0" por el texto proporcionado.
     * @param key Clave del texto.
     * @param text Texto que se desea insertar.
     * @return Recurso textual con la subcadena sustituida. */
    public static String getString(final String key, final String text) {
        try {
            return resourceBundle.getString(key).replace("%0", text); //$NON-NLS-1$
        }
        catch (final NullPointerException | MissingResourceException | ClassCastException  e) {
        	JmcLogger.severe("No se ha encontrado el recurso de texto con clave '" + key + "': " + e); //$NON-NLS-1$ //$NON-NLS-2$
            return '!' + key + '!';
        }
    }

    /** Recupera el texto identificado con la clave proporcionada.
     * @param key Clave del texto.
     * @return Recurso textual. */
    public static String getString(final String key) {
        try {
            return resourceBundle.getString(key);
        }
        catch (final NullPointerException | MissingResourceException | ClassCastException e) {
        	JmcLogger.severe("No se ha encontrado el recurso de texto con clave '" + key + "': " + e); //$NON-NLS-1$ //$NON-NLS-2$
            return '!' + key + '!';
        }
    }

}
