package es.gob.jmulticard.android.callbacks;

import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import android.app.Activity;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentTransaction;
import es.gob.jmulticard.card.dnie.AuthorizeCallback;
import es.gob.jmulticard.card.dnie.TextInputCallback;

/** CallbackHandler que gestiona los Callbacks de petici&oacute;n de informaci&oacute;n al usuario.
 * @author Sergio Mart&iacute;nez Rico. */
public class DnieNFCCallbackHandler implements CallbackHandler {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$
	private final Activity activity;
	private final DialogDoneChecker dialogDone;

	public DnieNFCCallbackHandler(final Activity ac, final DialogDoneChecker ddc) {
		this.activity = ac;
		this.dialogDone = ddc;
	}

	@Override
	public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {
		if (callbacks != null) {
			for (final Callback cb : callbacks) {

				if (cb instanceof PasswordCallback) {
					final PinDialog dialog = new PinDialog(
							false,
							this.activity,
							cb,
							this.dialogDone
						);

					final FragmentTransaction ft = ((FragmentActivity)this.activity).getSupportFragmentManager().beginTransaction();
					final ShowPinDialogTask spdt = new ShowPinDialogTask(dialog, ft, this.activity, this.dialogDone);
					final String input = spdt.getInput();

					((PasswordCallback) cb).setPassword(input.toCharArray());

					return;
				}

				if (cb instanceof TextInputCallback) {
					final PinDialog dialog = new PinDialog(
						true,
						this.activity,
						cb,
						this.dialogDone
					);

					final FragmentTransaction ft = ((FragmentActivity)this.activity).getSupportFragmentManager().beginTransaction();
					final ShowPinDialogTask spdt = new ShowPinDialogTask(dialog, ft, this.activity, this.dialogDone);
					final String input = spdt.getInput();

					((TextInputCallback) cb).setText(input);

					return;
				}

				if (cb instanceof AuthorizeCallback) {
					return;
				}

				LOGGER.severe(cb.getClass().getName());
			}
		}
		else {
			LOGGER.warning("Se ha recibido un array de Callbacks nulo"); //$NON-NLS-1$
			throw new UnsupportedCallbackException(null);
		}
	}
}
