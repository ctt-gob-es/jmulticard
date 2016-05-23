package es.gob.jmulticard.ui.passwordcallback.gui;

import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.jmulticard.ui.passwordcallback.Messages;

/** CallbackHandler que gestiona los Callbacks de petici&oacute;n de informaci&oacute;n al usuario en tarjetas CERES
 * @author Sergio Mart&iacute;nez Rico
 */
public class CeresCallbackHandler implements CallbackHandler {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$
	@Override
	public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {
		if (callbacks != null) {
			for (final Callback cb : callbacks) {
				if (cb instanceof PasswordCallback) {
					final CommonPasswordCallback uip = new CommonPasswordCallback(((PasswordCallback)cb).getPrompt(),
													Messages.getString("CommonPasswordCallback.2"), //$NON-NLS-1$
													false);
					((PasswordCallback)cb).setPassword(uip.getPassword());
					return;
				}
				LOGGER.severe(cb.getClass().getName());
			}
		}
		else {
			LOGGER.severe("Callbacks nulas"); //$NON-NLS-1$
		}
		throw new UnsupportedCallbackException(null);
	}
}
