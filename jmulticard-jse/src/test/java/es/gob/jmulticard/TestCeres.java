package es.gob.jmulticard;

import java.util.Arrays;

import javax.security.auth.callback.PasswordCallback;

import org.junit.Test;

import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.fnmt.ceres.Ceres;
import es.gob.jmulticard.jse.provider.JseCryptoHelper;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;


/** Pruebas de FNMT-CERES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestCeres {

	private static final String PIN = "\u00F1apa"; //$NON-NLS-1$

	final static class CachePasswordCallback extends PasswordCallback {

	    private static final long serialVersionUID = 816457144215238935L;

	    /** Contruye una Callback con una contrase&ntilde; preestablecida.
	     * @param password Contrase&ntilde;a por defecto. */
	    public CachePasswordCallback(final char[] password) {
	        super(">", false); //$NON-NLS-1$
	        this.setPassword(password);
	    }
	}

	/** Main.
	 * @param args
	 * @throws Exception */
	public static void main(final String[] args) throws Exception {
		final Ceres ceres = new Ceres(
			new SmartcardIoConnection(),
			new JseCryptoHelper()
		);
		ceres.setPasswordCallback(new CachePasswordCallback(PIN.toCharArray()));
		System.out.println(ceres.getCardName());
		System.out.println(Arrays.asList(ceres.getAliases()));
		System.out.println(ceres.getCertificate(ceres.getAliases()[0]));
		final PrivateKeyReference pkr = ceres.getPrivateKey(ceres.getAliases()[0]);
		System.out.println(
			HexUtils.hexify(
				ceres.sign("hola".getBytes(), "SHA1withRSA", pkr),  //$NON-NLS-1$//$NON-NLS-2$
				true
			)
		);
	}

	/** Prueba de introducci&oacute;n de PIN por UI, para comprobaci&oacute;n de PIN
	 * con caracteres especiales.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testCeresUIPasswordCallbackSpecialCharsOnPin() throws Exception {
		final Ceres ceres = new Ceres(
			new SmartcardIoConnection(),
			new JseCryptoHelper()
		);
		ceres.setPasswordCallback(
			new PasswordCallback("PIN de la tarjeta CERES", false) //$NON-NLS-1$
		);
		System.out.println(ceres.getCardName());
		System.out.println(Arrays.asList(ceres.getAliases()));
		System.out.println(ceres.getCertificate(ceres.getAliases()[0]));
		final PrivateKeyReference pkr = ceres.getPrivateKey(ceres.getAliases()[0]);
		System.out.println(
			HexUtils.hexify(
				ceres.sign("hola".getBytes(), "SHA1withRSA", pkr),  //$NON-NLS-1$//$NON-NLS-2$
				true
			)
		);
	}

}
