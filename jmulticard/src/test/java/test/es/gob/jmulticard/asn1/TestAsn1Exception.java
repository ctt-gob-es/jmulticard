/**
 *
 */
package test.es.gob.jmulticard.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.asn1.Asn1Exception;

/** Pruebas unitarias para la clase {@linkplain es.gob.jmulticard.asn1.Asn1Exception}
 * @author Alberto Mart&iacute;nez */
final class TestAsn1Exception {

    /** Test method for {@link es.gob.jmulticard.asn1.Asn1Exception#Asn1Exception(java.lang.String)}. */
	@SuppressWarnings("static-method")
	@Test
	void testAsn1ExceptionString() {
        Assertions.assertNotNull(new Asn1Exception("")); //$NON-NLS-1$
    }

    /** Test method for {@link es.gob.jmulticard.asn1.Asn1Exception#Asn1Exception(java.lang.Throwable)}. */
	@SuppressWarnings("static-method")
	@Test
	void testAsn1ExceptionThrowable() {
        Assertions.assertNotNull(new Asn1Exception(new Exception()));
    }

    /** Test method for {@link es.gob.jmulticard.asn1.Asn1Exception#Asn1Exception(java.lang.String, java.lang.Throwable)}. */
	@SuppressWarnings("static-method")
	@Test
	void testAsn1ExceptionStringThrowable() {
        Assertions.assertNotNull(new Asn1Exception("", new Exception())); //$NON-NLS-1$
    }
}