package test.es.gob.jmulticard.apdu;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.iso7816four.MseSetComputationApduCommand;
import es.gob.jmulticard.apdu.iso7816four.SelectDfByNameApduCommand;

/** Pruebas varias de diferentes APDU.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestApdus {

	/** Prueba de APDU de selecci&oacute;n de DF por nombre.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	void testSelectDfByName() throws Exception {
		final byte[] dfName = {
			(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x63, (byte) 0x50, (byte) 0x4B, (byte) 0x43,
			(byte) 0x53, (byte) 0x2D, (byte) 0x31, (byte) 0x35
		};
		final CommandApdu selectDfByName = new SelectDfByNameApduCommand(
			(byte) 0x00,
			dfName
		);
		Assertions.assertNotNull(selectDfByName);
		System.out.println(new String(dfName, StandardCharsets.UTF_8));
		System.out.println(
			HexUtils.hexify(selectDfByName.getBytes(), true)
		);
	}

	/** Prueba de la APDU ISO 7816-4 de gesti&oacute;n de entorno de seguridad para c&oacute;mputo de
     * firma electr&oacute;nica. */
	@SuppressWarnings("static-method")
	@Test
	void testMseSetComputation() {
		 final CommandApdu mseSetComputation = new MseSetComputationApduCommand(
			 (byte)0x01,
			 new byte[] {(byte)0x00},
			 new byte[] {(byte)0x02}
		 );
		 Assertions.assertNotNull(mseSetComputation);
		 System.out.println(
			 HexUtils.hexify(mseSetComputation.getBytes(), true)
		 );
	}
}
