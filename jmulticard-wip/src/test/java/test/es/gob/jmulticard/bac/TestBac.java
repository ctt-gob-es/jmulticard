package test.es.gob.jmulticard.bac;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.card.icao.WirelessInitializer;
import es.gob.jmulticard.card.icao.WirelessInitializerMrz;
import es.gob.jmulticard.card.icao.bac.Bac;
import es.gob.jmulticard.crypto.BcCryptoHelper;
import es.gob.jmulticard.jse.provider.ProviderUtil;

/** Pruebas de BAC.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestBac {

	//private static final String TEST_MRZ = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<L898902C<3UTO6908061F9406236<<<<<<<8"; //$NON-NLS-1$
	  private static final String TEST_MRZ = "P<ESPGARCIA<MERAS<CAPOTE<<TOMAS<<<<<<<<<<<<<AAA0023645ESP7501045M1907173A1183096000<<<04"; //$NON-NLS-1$

	/** Prueba de obtenci&oacute;n de inicializador a partir de MRZ,
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testMrz() throws Exception {
		final WirelessInitializer pi = WirelessInitializerMrz.deriveMrz(TEST_MRZ, new BcCryptoHelper());
		System.out.println(
			HexUtils.hexify(pi.getBytes(), true)
		);
	}

	/** Prueba completa de protocolo BAC.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita pasaporte")
	void testBac() throws Exception {
		Bac.doBac(TEST_MRZ, new BcCryptoHelper(), ProviderUtil.getDefaultConnection());
	}

}
