package test.es.gob.jmulticard.asn1;

import junit.framework.TestCase;

import org.junit.Assert;

import es.gob.jmulticard.asn1.Asn1SyntaxException;

/** Pruebas unitarias para la clase {@linkplain test.es.gob.jmulticard.asn1.Asn1SyntaxException}
 * @author Alberto Mart&iacute;nez */
public class TestAsn1SyntaxException extends TestCase {

    /** Test method for {@link test.es.gob.jmulticard.asn1.Asn1SyntaxException#Asn1SyntaxException(java.lang.String)}. */
    public final static void testAsn1SyntaxExceptionString() {
        Assert.assertNotNull(new Asn1SyntaxException("")); //$NON-NLS-1$
    }

    /** Test method for {@link test.es.gob.jmulticard.asn1.Asn1SyntaxException#Asn1SyntaxException(java.lang.Throwable)}. */
    public final static void testAsn1SyntaxExceptionThrowable() {
        Assert.assertNotNull(new Asn1SyntaxException(new Exception()));
    }

    /** Test method for {@link test.es.gob.jmulticard.asn1.Asn1SyntaxException#Asn1SyntaxException(java.lang.String, java.lang.Throwable)}. */
    public final static void testAsn1SyntaxExceptionStringThrowable() {
        Assert.assertNotNull(new Asn1SyntaxException("", new Exception())); //$NON-NLS-1$
    }
}