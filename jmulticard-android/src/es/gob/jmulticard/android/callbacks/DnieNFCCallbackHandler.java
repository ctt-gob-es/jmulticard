package test.es.gob.jmulticard.android.callbacks;

import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import android.app.Activity;
import android.support.v4.app.FragmentActivity;
import android.support.v4.app.FragmentTransaction;
import test.es.gob.jmulticard.callback.CustomAuthorizeCallback;
import test.es.gob.jmulticard.callback.CustomTextInputCallback;

/** CallbackHandler que gestiona los Callbacks de petici&oacute;n de informaci&oacute;n al usuario.
 * @author Sergio Mart&iacute;nez Rico. */
public class DnieNFCCallbackHandler implements CallbackHandler {

	private static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$
	private final Activity activity;
	private final DialogDoneChecker dialogDone;
	private CachePasswordCallback passwordCallback;

	/** CallbackHandler que gestiona los Callbacks de petici&oacute;n de informaci&oacute;n al usuario.
	 * @param ac Handler de la actividad desde la que se llama.
	 * @param ddc Instancia de la clase utilizada para utilizar wait() y notify() al esperar el PIN.
	 * @param passwordCallback Instancia que contiene el CAN pedido antes a la lectura NFC.*/
	public DnieNFCCallbackHandler(final Activity ac, final DialogDoneChecker ddc, final CachePasswordCallback passwordCallback) {
		this.activity = ac;
		this.dialogDone = ddc;
		this.passwordCallback = passwordCallback;
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
				String input;
				if (cb instanceof CustomTextInputCallback) {
					if(this.passwordCallback == null) {
						final PinDialog dialog = new PinDialog(
							true,
							this.activity,
							cb,
							this.dialogDone
						);

						final FragmentTransaction ft = ((FragmentActivity)this.activity).getSupportFragmentManager().beginTransaction();
						final ShowPinDialogTask spdt = new ShowPinDialogTask(dialog, ft, this.activity, this.dialogDone);
						input = spdt.getInput();
					}
					else {
						input = new String(this.passwordCallback.getPassword());
						// En caso de fallar el primer CAN lo pedira de nuevo al ususario
						this.passwordCallback = null;
					}

					((CustomTextInputCallback) cb).setText(input);

					return;
				}

				if (cb instanceof CustomAuthorizeCallback) {
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
