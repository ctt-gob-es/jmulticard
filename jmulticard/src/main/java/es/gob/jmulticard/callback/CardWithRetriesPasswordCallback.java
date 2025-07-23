package es.gob.jmulticard.callback;

import javax.security.auth.callback.PasswordCallback;

public class CardWithRetriesPasswordCallback extends PasswordCallback {

	private static final long serialVersionUID = 7929236918907338858L;
	
	private int retriesLeft = 0;

	public CardWithRetriesPasswordCallback(final String prompt, final boolean echoOn) {
		super(prompt, echoOn);
	}

	public void setRetriesLeft(final int retriesLeft) {
		this.retriesLeft = retriesLeft;
	}

	public int getRetriesLeft() {
		return this.retriesLeft;
	}

}
