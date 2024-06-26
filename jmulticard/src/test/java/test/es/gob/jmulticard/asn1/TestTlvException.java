package test.es.gob.jmulticard.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.asn1.TlvException;

/** Pruebas unitarias para la clase {@linkplain es.gob.jmulticard.asn1.TlvException}
 * @author Alberto Mart&iacute;nez */
final class TestTlvException {

    /** Test method for {@link es.gob.jmulticard.asn1.TlvException#TlvException(java.lang.String)} and
     * {@link es.gob.jmulticard.asn1.TlvException#TlvException(String, Throwable)}. */
	@SuppressWarnings("static-method")
	@Test
	void testCreationTlvException() {
        Assertions.assertNotNull(new TlvException("")); //$NON-NLS-1$
        Assertions.assertNotNull(new TlvException("", new Exception(""))); //$NON-NLS-1$ //$NON-NLS-2$
    }
}