package es.gob.jmulticard.jse.provider;

import java.security.KeyStore.PasswordProtection;

import javax.security.auth.callback.PasswordCallback;

/** <code>PasswordCallback</code> por defecto para pedir el PIN de una tarjeta.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CardPasswordCallback extends PasswordCallback {

	private static final long serialVersionUID = -2511696590746468782L;

	/** <code>PasswordProtection</code> para solicitar la contrase&ntilde;a. */
	private transient final PasswordProtection passp;

	/** Constructor.
	 * @param pp <code>PasswordProtection</code> para solicitar la contrase&ntilde;a.
	 * @param prompt Texto con el que solicitar la contrase&ntilde;a al usuario. */
	public CardPasswordCallback(final PasswordProtection pp, final String prompt) {
		super(prompt, false);
		if (pp == null) {
			throw new IllegalArgumentException(
				"El PasswordProtection no puede ser nulo" //$NON-NLS-1$
			);
		}
		this.passp = pp;
	}

	@Override
	public char[] getPassword() {
		return this.passp.getPassword();
	}

}
