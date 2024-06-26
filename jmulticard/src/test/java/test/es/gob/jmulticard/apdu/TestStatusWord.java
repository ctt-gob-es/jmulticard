package test.es.gob.jmulticard.apdu;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.StatusWord;

/** Prueba de la clase {@linkplain es.gob.jmulticard.apdu.StatusWord}
 * @author Alberto Mart&iacute;nez */
final class TestStatusWord {

    /** Prueba el funcionamiento de hashCode */
	@SuppressWarnings("static-method")
	@Test
    void testHashCode() {
        final StatusWord sw = new StatusWord((byte) 0x90, (byte) 0x00);
        Assertions.assertEquals(HexUtils.getShort(new byte[] {
                (byte) 0x90, (byte) 0x00
        }, 0), sw.hashCode());
    }

    /** Prueba el funcionamiento de getBytes */
	@SuppressWarnings("static-method")
	@Test
    void testGetBytes() {
        final StatusWord sw = new StatusWord((byte) 0x90, (byte) 0x00);
        final byte[] respuestaEsperada = {
                (byte) 0x90, (byte) 0x00
        };

        for (int i = 0; i < sw.getBytes().length; i++) {
            Assertions.assertEquals(respuestaEsperada[i], sw.getBytes()[i]);
        }
    }

    /** Prueba el funcionamiento de equals */
	@SuppressWarnings("static-method")
	@Test
	void testEqualsObject() {
        final StatusWord sw1 = new StatusWord((byte) 0x90, (byte) 0x00);
        final StatusWord sw2 = new StatusWord((byte) 0x90, (byte) 0x00);
        Assertions.assertEquals(sw1, sw2);
        Assertions.assertNotEquals(sw1, new StatusWord((byte) 0x60, (byte) 0x84));
        Assertions.assertNotEquals(sw1, String.valueOf(true));
    }
}