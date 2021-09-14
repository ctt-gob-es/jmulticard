package test.es.gob.jmulticard.apdu;

import org.junit.Assert;

import es.gob.jmulticard.apdu.ResponseApdu;
import junit.framework.TestCase;

/** Prueba de m&eacute;todos de la clase {@linkplain es.gob.jmulticard.apdu.ResponseApdu}
 * @author Alberto Mart&iacute;nez */
public final class TestResponseApdu extends TestCase {

    /** Test method for {@link es.gob.jmulticard.apdu.ResponseApdu#isOk()}. */
    public static void testIsOk() {
        Assert.assertFalse(new ResponseApdu(new byte[] { (byte) 0x90 }).isOk());
        Assert.assertTrue(new ResponseApdu(new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00 }).isOk());
    }
}