package es.gob.jmulticard;

import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.jmulticard.card.dnie.CustomAuthorizeCallback;
import es.gob.jmulticard.card.dnie.CustomTextInputCallback;

/** CallbackHandler que gestiona los Callbacks de petici&oacute;n de informaci&oacute;n al usuario.
 * @author Sergio Mart&iacute;nez Rico. */
public final class TestingDnieCallbackHandler implements CallbackHandler {

	private final String can;
	private final char[] pin;

	/** Construye un CallbackHandler de prueba.
	 * @param c CAN
	 * @param p PIN. */
	public TestingDnieCallbackHandler(final String c, final String p) {
		this.can = c;
		this.pin = p.toCharArray();
	}

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$
	@Override
	public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {
		if (callbacks != null) {
			for (final Callback cb : callbacks) {
				if (cb != null) {
					if (cb instanceof CustomTextInputCallback) {
						((CustomTextInputCallback)cb).setText(this.can);
						return;
					}
					else if (cb instanceof CustomAuthorizeCallback) {
						((CustomAuthorizeCallback)cb).setAuthorized(true);
						return;
					}
					else if (cb instanceof PasswordCallback) {
						((PasswordCallback)cb).setPassword(this.pin);
						return;
					}
					else {
						LOGGER.severe("Callback no soportada: " + cb.getClass().getName()); //$NON-NLS-1$
					}
				}
			}
		}
		else {
			LOGGER.warning("Se ha revibido un array de Callbacks nulo"); //$NON-NLS-1$
		}
		throw new UnsupportedCallbackException(null);
	}
}
