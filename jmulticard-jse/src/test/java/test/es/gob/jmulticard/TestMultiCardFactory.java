package test.es.gob.jmulticard;

import java.security.Provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import es.gob.jmulticard.jse.provider.JMultiCardProviderFactory;

/** Pruebas de la factor&iacute;a de proveedores para tarjetas soportadas.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestMultiCardFactory {

	/** Prueba de la factor&iacute;a de proveedores para tarjetas soportadas. */
	@SuppressWarnings("static-method")
	@Test
	@Disabled("Necesita tarjeta")
	void testMultiCardProviderFactory() {
		try {
			final Provider p = JMultiCardProviderFactory.getProvider();
			if (p == null) {
				System.out.println("No hay tarjetas soportadas insertadas"); //$NON-NLS-1$
			}
			else {
				System.out.println("Encontrada tarjeta, se usara el proveedor: " + p.getName()); //$NON-NLS-1$
			}
		}
		catch(final Exception e) {
			e.printStackTrace();
			Assertions.fail();
		}
	}
}
