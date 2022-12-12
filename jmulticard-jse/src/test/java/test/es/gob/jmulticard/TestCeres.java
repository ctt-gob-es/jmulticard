package test.es.gob.jmulticard;

import java.util.Arrays;

import javax.security.auth.callback.PasswordCallback;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.BcCryptoHelper;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.ceressc.CeresSc;
import es.gob.jmulticard.card.fnmt.ceres.Ceres;
import es.gob.jmulticard.jse.provider.CachePasswordCallback;
import es.gob.jmulticard.jse.provider.ProviderUtil;


/** Pruebas de FNMT-CERES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestCeres {

//	private static final char[] PIN = "eJh3Rhbf".toCharArray(); //$NON-NLS-1$
	private static final char[] PIN = "2gh4GRlJ".toCharArray(); //$NON-NLS-1$

	/** Main.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		final Ceres ceres = new Ceres(
			ProviderUtil.getDefaultConnection(),
			new BcCryptoHelper()
		);
		ceres.setPasswordCallback(new CachePasswordCallback(PIN));
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
		System.out.println(
			HexUtils.hexify(
				ceres.sign("manola".getBytes(), "SHA256withRSA", pkr),  //$NON-NLS-1$//$NON-NLS-2$
				true
			)
		);
	}

	/** Pruebas de CERES 4&#46;30.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testCeresSecureChannel() throws Exception {
		final CeresSc ceres430 = new CeresSc(
			ProviderUtil.getDefaultConnection(),
			new CachePasswordCallback(PIN),
			new BcCryptoHelper(),
			new TestingDnieCallbackHandler("can", PIN) //$NON-NLS-1$
		);

		ceres430.setPasswordCallback(new CachePasswordCallback(PIN));
		System.out.println(ceres430.getCardName());
		System.out.println(Arrays.asList(ceres430.getAliases()));
		System.out.println(ceres430.getCertificate(ceres430.getAliases()[0]));
		final PrivateKeyReference pkr = ceres430.getPrivateKey(ceres430.getAliases()[0]);
		System.out.println(
			HexUtils.hexify(
				ceres430.sign("hola".getBytes(), "SHA1withRSA", pkr),  //$NON-NLS-1$//$NON-NLS-2$
				true
			)
		);
	}

	/** Prueba de introducci&oacute;n de PIN por UI, para comprobaci&oacute;n de PIN
	 * con caracteres especiales.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testCeresUIPasswordCallbackSpecialCharsOnPin() throws Exception {
		final Ceres ceres = new Ceres(
			ProviderUtil.getDefaultConnection(),
			new BcCryptoHelper()
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