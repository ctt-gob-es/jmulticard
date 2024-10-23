package test.es.gob.jmulticard.apdu;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.apdu.ResponseApdu;

/** Prueba de la clase {@linkplain es.gob.jmulticard.apdu.ResponseApdu}
 * @author Alberto Mart&iacute;nez */
final class TestResponseApdu {

    /** Test method for {@link es.gob.jmulticard.apdu.ResponseApdu#isOk()}. */
	@SuppressWarnings("static-method")
	@Test
    void testIsOk() {
        Assertions.assertFalse(new ResponseApdu(new byte[] { (byte) 0x90 }).isOk());
        Assertions.assertTrue(new ResponseApdu(new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00 }).isOk());
    }
}