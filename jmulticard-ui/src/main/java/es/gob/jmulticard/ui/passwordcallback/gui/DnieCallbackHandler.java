package es.gob.jmulticard.ui.passwordcallback.gui;

import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.jmulticard.card.dnie.CustomAuthorizeCallback;
import es.gob.jmulticard.card.dnie.CustomTextInputCallback;
import es.gob.jmulticard.ui.passwordcallback.DialogBuilder;
import es.gob.jmulticard.ui.passwordcallback.Messages;

/** CallbackHandler que gestiona los Callbacks de petici&oacute;n de informaci&oacute;n al usuario.
 * @author Sergio Mart&iacute;nez Rico. */
public class DnieCallbackHandler implements CallbackHandler {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$
	@Override
	public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {
		if (callbacks != null) {
			for (final Callback cb : callbacks) {
				if (cb != null) {
					if (cb instanceof CustomTextInputCallback) {
						final UIPasswordCallbackCan uip = new UIPasswordCallbackCan(
							Messages.getString("CanPasswordCallback.0"), //$NON-NLS-1$
							null,
							Messages.getString("CanPasswordCallback.0"), //$NON-NLS-1$
							Messages.getString("CanPasswordCallback.2") //$NON-NLS-1$
						);
						((CustomTextInputCallback)cb).setText(new String(uip.getPassword()));
						return;
					}
					else if (cb instanceof CustomAuthorizeCallback) {
						DialogBuilder.showSignatureConfirmDialog((CustomAuthorizeCallback)cb);
						return;
					}
					else if (cb instanceof PasswordCallback) {
						final CommonPasswordCallback uip = new CommonPasswordCallback(
							Messages.getString("CommonPasswordCallback.4") + ((PasswordCallback)cb).getPrompt(), //$NON-NLS-1$
							Messages.getString("CommonPasswordCallback.1"), //$NON-NLS-1$
							true
						);
						((PasswordCallback)cb).setPassword(uip.getPassword());
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
