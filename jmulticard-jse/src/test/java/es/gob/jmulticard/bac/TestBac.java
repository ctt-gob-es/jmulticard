package es.gob.jmulticard.bac;

import org.junit.Ignore;
import org.junit.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.JseCryptoHelper;
import es.gob.jmulticard.card.bac.Bac;
import es.gob.jmulticard.card.pace.PaceInitializer;
import es.gob.jmulticard.card.pace.PaceInitializerMrz;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;

/** Pruebas de BAC.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestBac {

	//private static final String TEST_MRZ = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<L898902C<3UTO6908061F9406236<<<<<<<8"; //$NON-NLS-1$
	  private static final String TEST_MRZ = "P<ESPGARCIA<MERAS<CAPOTE<<TOMAS<<<<<<<<<<<<<AAA0023645ESP7501045M1907173A1183096000<<<04";

	/** Prueba de obtenci&oacute;n de inicializador a partir de MRZ,
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testMrz() throws Exception {
		final PaceInitializer pi = PaceInitializerMrz.deriveMrz(TEST_MRZ);
		System.out.println(
			HexUtils.hexify(pi.getBytes(), true)
		);
	}

	/** Prueba completa de protocolo BAC.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Ignore
	public void testBac() throws Exception {
		Bac.doBac(TEST_MRZ, new JseCryptoHelper(), new SmartcardIoConnection());
	}

}
