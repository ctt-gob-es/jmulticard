package test.es.gob.jmulticard;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.junit.Assert;
import org.junit.Test;

import es.gob.jmulticard.HexUtils;
import junit.framework.TestCase;

/** Pruebas de los m&eacute;todos definidos en la clase de utilidades {@linkplain es.gob.jmulticard.HexUtils}
 * @author Alberto Mart&iacute;nez */
public class TestHexUtils extends TestCase {

    private static final byte[] HEXSTRING = "Prueba".getBytes(); //$NON-NLS-1$

    /** Prueba el m&eacute;todo {@linkplain es.gob.jmulticard.HexUtils#arrayEquals(byte[], byte[])} */
    public static void testArrayEqualsByteArrayByteArray() {
        final byte[] result1 = "Prueba".getBytes(); //$NON-NLS-1$
        final byte[] result2 = "Test1".getBytes(); //$NON-NLS-1$
        Assert.assertTrue(HexUtils.arrayEquals(HEXSTRING, result1));
        Assert.assertFalse(HexUtils.arrayEquals(HEXSTRING, result2));
    }

    /** Prueba el m&eacute;todo {@linkplain es.gob.jmulticard.HexUtils#arrayEquals(byte[], int, int, byte[], int, int)} */
    public static void testArrayEqualsByteArrayIntIntByteArrayIntInt() {
        final byte[] result1 = "Prueba".getBytes(); //$NON-NLS-1$
        final byte[] result2 = "Trueba".getBytes(); //$NON-NLS-1$
        final byte[] result3 = "Otra".getBytes(); //$NON-NLS-1$
        Assert.assertTrue(HexUtils.arrayEquals(HEXSTRING, 0, HEXSTRING.length, result1, 0, result1.length));
        Assert.assertFalse(HexUtils.arrayEquals(HEXSTRING, 1, HEXSTRING.length, result2, 1, result2.length));
        Assert.assertFalse(HexUtils.arrayEquals(HEXSTRING, 0, HEXSTRING.length, result3, 0, result3.length));
    }

    /** Prueba el m&eacute;todo {@linkplain es.gob.jmulticard.HexUtils#getShort(byte[], int)} */
    public static void testGetShort() {
        Assert.assertEquals(20594, HexUtils.getShort(HEXSTRING, 0));
        Assert.assertEquals(29301, HexUtils.getShort(HEXSTRING, 1));
    }

    /** Prueba el m&eacute;todo {@linkplain es.gob.jmulticard.HexUtils#getUnsignedInt(byte[], int)} */
    public static void testGetUnsignedInt() {
        Assert.assertEquals(20594, HexUtils.getUnsignedInt(HEXSTRING, 0));
        Assert.assertEquals(29301, HexUtils.getUnsignedInt(HEXSTRING, 1));
    }

    /** Prueba el m&eacute;todo {@linkplain es.gob.jmulticard.HexUtils#hexify(byte[], boolean)} */
    public static void testHexify() {
        Assert.assertEquals("null", HexUtils.hexify(null, true)); //$NON-NLS-1$
        Assert.assertEquals("50-72-75-65-62-61", HexUtils.hexify(HEXSTRING, true)); //$NON-NLS-1$
        Assert.assertEquals("507275656261", HexUtils.hexify(HEXSTRING, false)); //$NON-NLS-1$
        Assert.assertEquals("43-61-64-65-6E-61-20-6C-61-72-67-61-20-64-65-20\n65-6A-65-6D-70-6C-6F-20-70-61-72-61-20-6F-62-74\n65-6E-65-72-20-72-65-74-6F-72-6E-6F-73-20-64-65\n20-63-61-72-72-6F-2E", HexUtils.hexify("Cadena larga de ejemplo para obtener retornos de carro.".getBytes(), true)); //$NON-NLS-1$ //$NON-NLS-2$
    }

    /** Prueba el m&eacute;todo {@linkplain es.gob.jmulticard.HexUtils#subArray(byte[], int, int)} */
    public static void testSubArray() {
        final byte[] expectedResult = "rue".getBytes(); //$NON-NLS-1$
        final byte[] result = HexUtils.subArray(HEXSTRING, 1, 3);
        for (int i = 0; i < result.length; i++) {
            Assert.assertEquals("El valor esperado " + expectedResult[i] + " no coincide con el obtenido " + result[i], expectedResult[i], result[i]); //$NON-NLS-1$ //$NON-NLS-2$
        }

        Assert.assertNull(HexUtils.subArray(HEXSTRING, 0, 0));
        Assert.assertNull(HexUtils.subArray(HEXSTRING, 10, 4));
    }

    /** Prueba el m&eacute;todo {@linkplain es.gob.jmulticard.HexUtils#xor(byte[], byte[])} */
    public static void testXor() {
        final byte[] result = HexUtils.xor(HEXSTRING, HEXSTRING);
        final byte[] array = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        HexUtils.xor(HEXSTRING, array);

        final byte[] expectedResult = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        for (int i = 0; i < result.length; i++) {
            Assert.assertEquals(expectedResult[i], result[i]);
        }
    }

    /** Pruebas de longitud de huella.
     * @param args No se usa.
     * @throws Exception En cualquier error. */
    public static void main(final String[] args) throws Exception {
    	System.out.println(MessageDigest.getInstance("SHA1").getDigestLength()); //$NON-NLS-1$
    	System.out.println(MessageDigest.getInstance("SHA-256").getDigestLength()); //$NON-NLS-1$
    	System.out.println(MessageDigest.getInstance("SHA-384").getDigestLength()); //$NON-NLS-1$
    	System.out.println(MessageDigest.getInstance("SHA-512").getDigestLength()); //$NON-NLS-1$
    }

    @Test
    public void testBiByteValue() {
    	for (int i=0;i<20;i++) {
    		final byte[] b = new byte[3];
    		new SecureRandom().nextBytes(b);
    		final BigInteger bi = new BigInteger(b);
    		System.out.println(HexUtils.hexify(b, false) + " -> " + HexUtils.hexify(new byte[] { bi.byteValue() }, false)); //$NON-NLS-1$
    	}
    }
}