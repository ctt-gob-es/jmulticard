package test.es.gob.jmulticard.ui.passwordcallback;

import org.junit.Assert;

import es.gob.jmulticard.CancelledOperationException;
import junit.framework.TestCase;

/** Pruebas de cancelaci&oacute;n de operaciones.
 * @author Alberto Mart&iacute;nez. */
public final class TestCancelledOperationException extends TestCase {

    /** Test method. */
    public final static void testCancelledOperationExceptionString() {
        Assert.assertNotNull(new CancelledOperationException("Operacion cancelada")); //$NON-NLS-1$
    }
}