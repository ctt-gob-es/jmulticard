package es.gob.jmulticard;

import org.junit.Test;

import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.card.dnie.Dnie;
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

}
