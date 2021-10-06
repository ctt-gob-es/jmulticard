package test.es.gob.jmulticard;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.jmulticard.callback.CustomAuthorizeCallback;

/** CallbackHandler que gestiona los Callbacks de petici&oacute;n de informaci&oacute;n al usuario.
 * @author Sergio Mart&iacute;nez Rico. */
public final class TestingDnieCallbackHandler implements CallbackHandler {

	private final String can;
	private final char[] pin;

	/** Construye un CallbackHandler de prueba.
	 * @param c CAN
	 * @param p PIN. */
	public TestingDnieCallbackHandler(final String c, final String p) {
		this.can = c;
		this.pin = p.toCharArray();
	}

	/** Construye un CallbackHandler de prueba.
	 * @param c CAN
	 * @param p PIN. */
	public TestingDnieCallbackHandler(final String c, final char[] p) {
		this.can = c;
		this.pin = p;
	}

	private static final Logger LOGGER = Logger.getLogger("test.es.gob.jmulticard"); //$NON-NLS-1$

	@Override
	public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {
		if (callbacks != null) {
			for (final Callback cb : callbacks) {
				if (cb != null) {
					if (
						"test.es.gob.jmulticard.callback.CustomTextInputCallback".equals(cb.getClass().getName()) || //$NON-NLS-1$
						"javax.security.auth.callback.TextInputCallback".equals(cb.getClass().getName()) //$NON-NLS-1$
					) {
						try {
							final Method m = cb.getClass().getMethod("setText", String.class); //$NON-NLS-1$
							m.invoke(cb, this.can);
						}
						catch (final NoSuchMethodException    |
							         SecurityException        |
							         IllegalAccessException   |
							         IllegalArgumentException |
							         InvocationTargetException e) {
							throw new UnsupportedCallbackException(
								cb,
								"No se ha podido invocar al metodo 'setText' de la callback: " + e //$NON-NLS-1$
							);
						}
					}
					else if (cb instanceof CustomAuthorizeCallback) {
						((CustomAuthorizeCallback)cb).setAuthorized(true);
					}
					else if (cb instanceof PasswordCallback) {
						((PasswordCallback)cb).setPassword(this.pin);
					}
					else {
						throw new UnsupportedCallbackException(cb);
					}
				}
			}
		}
		else {
			LOGGER.warning("Se ha recibido un array de Callbacks nulo"); //$NON-NLS-1$
		}
	}
}
