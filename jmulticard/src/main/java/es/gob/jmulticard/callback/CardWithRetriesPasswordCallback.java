package es.gob.jmulticard.callback;

import javax.security.auth.callback.PasswordCallback;

/** <i>Callback</i> de solicitud de PIN con intentos restantes para tarjetas.
 * <code>javax.security.auth.callback.PasswordCallback</code>. */
public class CardWithRetriesPasswordCallback extends PasswordCallback {

	private static final long serialVersionUID = 7929236918907338858L;
	
	/** Intentos restantes para la tarjeta */
	private int retriesLeft = 0;

	
	public CardWithRetriesPasswordCallback(final String prompt, final boolean echoOn) {
		super(prompt, echoOn);
	}

	/**
	 * Asigna los intentos que le quedan a la tarjeta.
	 * @param retriesLeft Intentos restantes.
	 */
	public void setRetriesLeft(final int retriesLeft) {
		this.retriesLeft = retriesLeft;
	}

	/**
	 * Devuelve los intentos restantes para la tarjeta.
	 * @return Intentos restantes.
	 */
	public int getRetriesLeft() {
		return this.retriesLeft;
	}

}
