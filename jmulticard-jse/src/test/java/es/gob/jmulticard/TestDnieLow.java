package es.gob.jmulticard;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.Dnie3Dg01Mrz;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.card.dnie.DnieSubjectPrincipalParser;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de operaciones en DNIe sin PIN ni CAN.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestDnieLow {

	/** Prueba de lectura sin PIN de los datos del titular.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDnieReadSubject() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			new SmartcardIoConnection(),
			null,
			new JseCryptoHelper(),
			null,
			false
		);
		final Cdf cdf = dnie.getCdf();
		System.out.println(cdf);
		System.out.println();
		System.out.println(new DnieSubjectPrincipalParser(cdf.getCertificateSubjectPrincipal(0)));
	}

	/** Prueba de lectura de DG en DNIe 3.0.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testDnieReadDgs() throws Exception {
		final Dnie dnie = DnieFactory.getDnie(
			new SmartcardIoConnection(),
			null,
			new JseCryptoHelper(),
			null,
			false
		);
		System.out.println();
		System.out.println(dnie);
		System.out.println();
		if (!(dnie instanceof Dnie3)) {
			System.out.println("No es un DNIe v3.0"); //$NON-NLS-1$
			return;
		}

		dnie.openSecureChannelIfNotAlreadyOpened();

		final Dnie3 dnie3 = (Dnie3) dnie;

		final byte[] com = dnie3.getCOM();
		System.out.println(new String(com));
		System.out.println();

		final Dnie3Dg01Mrz dg1 = dnie3.getMrz();
		System.out.println(dg1);
		System.out.println();

		final byte[] dg11 = dnie3.getDg11();
		System.out.println(new String(dg11));
		System.out.println();

	}
}
