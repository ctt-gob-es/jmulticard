package com.accenture.es.hps;

/** Prueba de lectura de datos ICAO usando clase de envoltura.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestView {

	/** Main para pruebas.
	 * @param args No se usa. */
	public static void main(final String[] args) {
		getViewData();
	}

	/** Obtiene los datos necesarios para el visor del DNIe. */
	public static void getViewData() {
		final Dnie3ObcWrapperView wrView = new Dnie3ObcWrapperView();
		final String can = "123456"; //$NON-NLS-1$
		final String viewData = wrView.getDnieVisualData(can);
		System.out.println(viewData);
	}
}
