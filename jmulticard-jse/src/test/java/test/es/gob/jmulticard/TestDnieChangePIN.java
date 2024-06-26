package test.es.gob.jmulticard;

import javax.security.auth.callback.PasswordCallback;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.crypto.BcCryptoHelper;
import es.gob.jmulticard.jse.provider.ProviderUtil;

/** Pruebas de cambio de PIN.
 * @author Sergio Mart&iacute;nez Rico. */
final class TestDnieChangePIN {

	/** <code>passwordCallback</code> que cachea el PIN. */
	private static final class CachePasswordCallback extends PasswordCallback {

	    private static final long serialVersionUID = 816457144215238935L;

	    /** Construye una <i>Callback</i> con una contrase&ntilde; preestablecida.
	     * @param password Contrase&ntilde;a por defecto. */
	    public CachePasswordCallback(final char[] password) {
	        super(">", false); //$NON-NLS-1$
	        setPassword(password);
	    }
	}

	/** Llamada a las pruebas a ejecutar
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		new TestDnieChangePIN().testChangePIN();
	}

	/** Test para probar el cambio de PIN tras la apertura del canal seguro.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testChangePIN() throws Exception {
		final CachePasswordCallback cpc = new CachePasswordCallback("password".toCharArray()); //$NON-NLS-1$
		final ApduConnection ac = ProviderUtil.getDefaultConnection();
		final Dnie dni = DnieFactory.getDnie(ac , cpc, new BcCryptoHelper(), null);
		Assertions.assertNotNull(dni);
		dni.changePIN("password", "pinNuevo"); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
