package es.gob.jmulticard.ui.passwordcallback.gui;

/**
 * Resultado del dialogo de solicitud de contrase&ntilde;a.
 */
public class PasswordResult {

	private char[] password;

	private boolean useCache;

	public PasswordResult(final char[] password) {
		this.password = password != null ? password.clone() : null;
		this.useCache = false;
	}

	public PasswordResult(final char[] password, final boolean useCache) {
		this.password = password != null ? password.clone() : null;
		this.useCache = useCache;
	}

	public char[] getPassword() {
		return this.password != null ? this.password.clone() : null;
	}

	public boolean isUseCache() {
		return this.useCache;
	}

	public void clear() {
		if (this.password != null) {
			for (int i = 0; i < this.password.length; i++) {
				this.password[i] = '\0';
			}
			this.password = null;
		}
		this.useCache = false;
	}
}
