package test.es.gob.jmulticard.ui.passwordcallback;

import org.junit.Assert;
import org.junit.Test;

import es.gob.jmulticard.ui.passwordcallback.Messages;
import junit.framework.TestCase;

/** @author Alberto Mart&iacute;nez */
public class TestMessages extends TestCase {

	/** Prueba de la obtenci&oacute;n de texto. */
	@Test
	public final static void testGetString() {
        Assert.assertEquals("##ERROR## Cadena no disponible: Cadena que no existe", Messages.getString("Cadena que no existe")); //$NON-NLS-1$ //$NON-NLS-2$
    }
}