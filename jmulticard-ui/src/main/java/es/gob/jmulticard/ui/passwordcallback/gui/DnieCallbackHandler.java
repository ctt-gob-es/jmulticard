package es.gob.jmulticard.ui.passwordcallback.gui;

import java.io.IOException;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import es.gob.jmulticard.ui.passwordcallback.DialogBuilder;
import es.gob.jmulticard.ui.passwordcallback.Messages;

/** CallbackHandler que gestiona los Callbacks de petici&oacute;n de informaci&oacute;n al usuario
 * @author Sergio Mart&iacute;nez Rico
 */
public class DnieCallbackHandler implements CallbackHandler {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$
	@Override
	public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		if (callbacks != null) {
			for (final Callback cb : callbacks) {
				if (cb instanceof TextInputCallback) {
					DialogBuilder.getCan((TextInputCallback)cb);
					return;
				}
				else if (cb instanceof AuthorizeCallback) {
					DialogBuilder.showSignatureConfirmDialog((AuthorizeCallback)cb);
					return;
				}
				else if (cb instanceof PasswordCallback) {
					final CommonPasswordCallback uip = new CommonPasswordCallback(((PasswordCallback)cb).getPrompt(),
													Messages.getString("CommonPasswordCallback.1")); //$NON-NLS-1$
					((PasswordCallback)cb).setPassword(uip.getPassword());
					return;
				}
				else {
					LOGGER.severe(cb.getClass().getName());
				}
			}
		}
		else {
			LOGGER.severe("Callbacks nulas"); //$NON-NLS-1$
		}
		throw new UnsupportedCallbackException(null);
	}
}
