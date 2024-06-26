package test.es.gob.jmulticard.card;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.card.CryptoCardException;

/** Pruebas unitarias para la clase {@linkplain es.gob.jmulticard.card.CryptoCardException}
 * @author Alberto Mart&iacute;nez */
final class TestCryptoCardException {

    /** Test method for {@link es.gob.jmulticard.card.CryptoCardException#CryptoCardException()}. */
	@SuppressWarnings("static-method")
	@Test
	void testCryptoCardException() {
        Assertions.assertNotNull(new CryptoCardException());
    }

    /** Test method for {@link es.gob.jmulticard.card.CryptoCardException#CryptoCardException(java.lang.String)}. */
	@SuppressWarnings("static-method")
	@Test
	void testCryptoCardExceptionString() {
        Assertions.assertNotNull(new CryptoCardException("")); //$NON-NLS-1$
    }

    /** Test method for {@link es.gob.jmulticard.card.CryptoCardException#CryptoCardException(java.lang.String, java.lang.Throwable)}. */
	@SuppressWarnings("static-method")
	@Test
	void testCryptoCardExceptionStringThrowable() {
        Assertions.assertNotNull(new CryptoCardException("", new Exception())); //$NON-NLS-1$
    }
}