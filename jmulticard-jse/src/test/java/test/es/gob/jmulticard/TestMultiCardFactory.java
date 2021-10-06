package test.es.gob.jmulticard;

import java.security.Provider;

import org.junit.Test;

import es.gob.jmulticard.jse.provider.JMultiCardProviderFactory;

/** Pruebas de la factor&iacute;a de proveedores para tarjetas soportadas.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestMultiCardFactory {

	/** Prueba de la factor&iacute;a de proveedores para tarjetas soportadas. */
	@SuppressWarnings("static-method")
	@Test
	public void testMultiCardProviderFactory() {
		final Provider p = JMultiCardProviderFactory.getProvider();
		if (p == null) {
			System.out.println("No hay tarjetas soportadas insertadas"); //$NON-NLS-1$
		}
		else {
			System.out.println("Encontrada tarjeta, se usara el proveedor: " + p.getName()); //$NON-NLS-1$
		}
	}
}
