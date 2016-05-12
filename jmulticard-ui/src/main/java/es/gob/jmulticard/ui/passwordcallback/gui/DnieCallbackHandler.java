package es.gob.jmulticard.ui.passwordcallback.gui;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.callback.CallbackHandler;

import es.gob.jmulticard.ui.passwordcallback.DialogBuilder;
import es.gob.jmulticard.ui.passwordcallback.Messages;

public class DnieCallbackHandler implements CallbackHandler {

	@Override
	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		if (callbacks != null) {
			for (Callback cb : callbacks) {
				if (cb instanceof TextInputCallback) {
					((TextInputCallback)cb).setText(DialogBuilder.getCan(cb));
					return;
				} 
				else if (cb instanceof ConfirmationCallback) {
					((ConfirmationCallback) cb).setSelectedIndex(DialogBuilder.showSignatureConfirmDialog(cb));
					return;
				}
				else if (cb instanceof PasswordCallback) {
					CommonPasswordCallback uip = new CommonPasswordCallback(((PasswordCallback)cb).getPrompt(),
													Messages.getString("CommonPasswordCallback.1"));
					((PasswordCallback)cb).setPassword(uip.getPassword());
					return;
				}
				else {
					System.out.println(cb.getClass().getName());
				}
			}
		}
		else {
			System.out.println("Callbacks nulas");
		}
		throw new UnsupportedCallbackException(null);
	}
}
