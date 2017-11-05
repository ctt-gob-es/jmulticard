package es.gob.jmulticard;

import java.security.cert.X509Certificate;

import org.junit.Test;

import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.gide.smartcafe.AetPkcs15Applet;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCard;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;
import test.es.gob.jmulticard.apdu.connection.cwa14890.CachePasswordCallback;

/** Pruebas de las tarjetas G&amp;D de ACCV
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class TestAccv {

	/** Prueba de lectura de certificados.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testReadCertificates() throws Exception {
		final CryptoCard card = new AetPkcs15Applet(
			new SmartcardIoConnection()
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
		System.out.println("Primer certificado encontrado: " + AOUtil.getCN(c)); //$NON-NLS-1$
	}

	/** Prueba de verificaci&oacute;n de PIN.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testVerifyPin() throws Exception {
		final char[] pin = "11111111".toCharArray(); //$NON-NLS-1$
		final Iso7816FourCard card = new AetPkcs15Applet(
			new SmartcardIoConnection()
		);
		card.verifyPin(new CachePasswordCallback(pin));
	}

}
