package test.es.gob.jmulticard;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.logging.Logger;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.jmulticard.callback.CustomTextInputCallback;

/** <code>CallbackHandler</code> que gestiona los <i>Callbacks</i> de petici&oacute;n de
 * informaci&oacute;n al usuario.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Sergio Mart&iacute;nez Rico. */
public final class TestingDnieCallbackHandler implements CallbackHandler {

	private final String can;
	private final char[] pin;

	/** Construye un <code>CallbackHandler</code> de prueba.
	 * @param c CAN.
	 * @param p PIN. */
	public TestingDnieCallbackHandler(final String c, final String p) {
		can = c;
		pin = p != null ? p.toCharArray() : null;
	}

	/** Construye un <code>CallbackHandler</code> de prueba.
	 * @param c CAN.
	 * @param p PIN. */
	public TestingDnieCallbackHandler(final String c, final char[] p) {
		can = c;
		pin = p != null ? p.clone() : null;
	}

	private static final Logger LOGGER = Logger.getLogger(TestingDnieCallbackHandler.class.getName());

	@Override
	public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {
		if (callbacks != null) {
			for (final Callback cb : callbacks) {
				if (cb != null) {
					if (
						"javax.security.auth.callback.TextInputCallback".equals(cb.getClass().getName()) //$NON-NLS-1$
					) {
						try {
							final Method m = cb.getClass().getMethod("setText", String.class); //$NON-NLS-1$
							m.invoke(cb, can);
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
					else if (cb instanceof CustomTextInputCallback) {
						((CustomTextInputCallback)cb).setText(can);
					}
					else if (cb instanceof PasswordCallback) {
						((PasswordCallback)cb).setPassword(pin);
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
