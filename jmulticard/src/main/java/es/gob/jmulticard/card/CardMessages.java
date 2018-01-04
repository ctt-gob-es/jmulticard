package es.gob.jmulticard.card;

import java.util.ResourceBundle;

/** Gestor de mensajes de las tarjetas (principalmente <code>PasswordCallbacks</code>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CardMessages {

	private static final String BUNDLE_NAME = "cardmessages"; //$NON-NLS-1$

	private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle(BUNDLE_NAME);

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
            return RESOURCE_BUNDLE.getString(key).replace("%0", text); //$NON-NLS-1$
        }
        catch (final Exception e) {
            return '!' + key + '!';
        }
    }

}
