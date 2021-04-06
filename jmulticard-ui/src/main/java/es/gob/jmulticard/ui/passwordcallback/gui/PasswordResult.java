package es.gob.jmulticard.ui.passwordcallback.gui;

import java.util.Arrays;

/** Resultado del di&aacute;logo de solicitud de contrase&ntilde;a. */
final class PasswordResult {

	private char[] password;

	private boolean useCache;

	PasswordResult(final char[] password) {
		this.password = password != null ? password.clone() : null;
		this.useCache = false;
	}

	PasswordResult(final char[] password, final boolean useCache) {
		this.password = password != null ? password.clone() : null;
		this.useCache = useCache;
	}

	char[] getPassword() {
		return this.password != null ? this.password.clone() : null;
	}

	boolean isUseCache() {
		return this.useCache;
	}

	void clear() {
		if (this.password != null) {
			Arrays.fill(this.password, '\0');
			this.password = null;
		}
		this.useCache = false;
	}
}
