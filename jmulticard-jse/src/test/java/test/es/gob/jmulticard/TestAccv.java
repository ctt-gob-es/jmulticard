package test.es.gob.jmulticard;

import java.security.cert.X509Certificate;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.BcCryptoHelper;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.gide.smartcafe.SmartCafePkcs15Applet;
import es.gob.jmulticard.card.iso7816four.AbstractIso7816FourCard;
import es.gob.jmulticard.jse.provider.CachePasswordCallback;
import es.gob.jmulticard.jse.provider.ProviderUtil;


/** Pruebas de las tarjetas G&amp;D de ACCV.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestAccv {

	private static final char[] PIN = "11111111".toCharArray(); //$NON-NLS-1$
	//private static final char[] PIN = "96824042".toCharArray(); //$NON-NLS-1$
	//private static final char[] PIN = "77772916".toCharArray(); //$NON-NLS-1$

	/** Prueba de lectura de certificados.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testReadCertificates() throws Exception {
		final CryptoCard card = new SmartCafePkcs15Applet(
			ProviderUtil.getDefaultConnection(),
			new BcCryptoHelper()
		);
		final String[] aliases = card.getAliases();
		if (aliases.length < 1) {
			System.out.println("La tarjeta no tiene certificados"); //$NON-NLS-1$
			return;
		}
		final String selectedAlias = aliases[0];
		System.out.println("Alias encontrados:"); //$NON-NLS-1$
		for (final String alias : aliases) {
			System.out.println("  " + alias); //$NON-NLS-1$
		}
		System.out.println();
		final X509Certificate c = card.getCertificate(selectedAlias);
		System.out.println("Primer certificado encontrado: " + c.getSubjectX500Principal()); //$NON-NLS-1$
	}

	/** Prueba de verificaci&oacute;n de PIN.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testVerifyPin() throws Exception {
		final AbstractIso7816FourCard card = new SmartCafePkcs15Applet(
			ProviderUtil.getDefaultConnection(),
			new BcCryptoHelper()
		);
		card.verifyPin(new CachePasswordCallback(PIN));
	}

	/** Prueba de firma.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testSign() throws Exception {
		final SmartCafePkcs15Applet card = new SmartCafePkcs15Applet(
			ProviderUtil.getDefaultConnection(),
			new BcCryptoHelper()
		);
		card.setPasswordCallback(new CachePasswordCallback(PIN));
		final PrivateKeyReference pkr = card.getPrivateKey(card.getAliases()[0]);
		final byte[] sign = card.sign("Hola mundo!".getBytes(), "SHA512withRSA", pkr); //$NON-NLS-1$ //$NON-NLS-2$
		System.out.println(HexUtils.hexify(sign, false));
	}

//	/** Prueba de verificaci&oacute;n de intentos restantes de PIN.
//	 * @throws Exception En cualquier error. */
//	@SuppressWarnings("static-method")
//	@Test
//	public void testPinRetriesLeft() throws Exception {
//		final SmartCafePkcs15Applet card = new SmartCafePkcs15Applet(
//			new SmartcardIoConnection(),
//	        new BcCryptoHelper()
//		);
//		System.out.println(
//			"INTENTOS DE PIN RESTANTES: " + card.getPinRetriesLeft() //$NON-NLS-1$
//		);
//	}

}
