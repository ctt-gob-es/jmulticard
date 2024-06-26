package test.es.gob.jmulticard.asn1.der;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.DerBoolean;

/** @author Alberto Mart&iacute;nez */
final class TestDerBoolean {

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		new TestDerBoolean().testGetBytes();
	}

    /** Test method for {@link es.gob.jmulticard.asn1.DecoderObject#setDerValue(byte[])}. */
	@SuppressWarnings("static-method")
	@Test
	void testSetDerValueWithNullArgumentMustGenerateIllegalArgumentException() {
        final DerBoolean db = new DerBoolean();
        try {
            db.setDerValue(null);
        }
        catch (final Exception e) {
            if (!(e instanceof IllegalArgumentException)) {
                Assertions.fail("Se esperaba " + IllegalArgumentException.class.getName() + " pero se obtuvo " + e.getClass().getName()); //$NON-NLS-1$ //$NON-NLS-2$
            }
        }
    }

    /** Prueba para {@link es.gob.jmulticard.asn1.DecoderObject#getBytes()}.
     * @throws TlvException Si no se puede crear el TLV.
     * @throws Asn1Exception Si falla la creaci&oacute;n del tipo ASN1. */
	@SuppressWarnings("static-method")
	@Test
	void testGetBytes() throws Asn1Exception, TlvException {
        final DerBoolean db = new DerBoolean();
        db.setDerValue(
    		new byte[] {
                (byte) 0x01, (byte) 0x01, (byte) 0x00
    		}
		);
        Assertions.assertEquals(
    		"010100", //$NON-NLS-1$
    		HexUtils.hexify(db.getBytes(), false),
        	"Error de decodificacion DER" //$NON-NLS-1$
		);
    }

    /** Test method for {@link es.gob.jmulticard.asn1.DecoderObject#checkTag(byte)}. */
	@SuppressWarnings("static-method")
	@Test
	void testCheckTagWithWrongTagMustThrowException() {
        try {
            final DerBoolean db = new DerBoolean();
            db.checkTag((byte) 0x02);
        }
        catch(final Asn1Exception e) {
        	System.out.println("Todo normal, ha saltado " + e); //$NON-NLS-1$
        }
        catch(final Exception e) {
            Assertions.fail("Se esperaba " + Asn1Exception.class.getName() + " pero se obtuvo " + e.getClass().getName()); //$NON-NLS-1$ //$NON-NLS-2$
        }
    }
}