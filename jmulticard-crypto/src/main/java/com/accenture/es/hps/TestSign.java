package com.accenture.es.hps;

/** Prueba de firma usando clase de envoltura.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestSign {

	/** Main para pruebas.
	 * @param args No se usa. */
	public static void main(final String[] args) {
		signData();
	}

	/** Hace una firma con DNIe. */
	public static void signData() {
		final Dnie3ObcWrapperSign wrSign = new Dnie3ObcWrapperSign();
		final String pin = "pinpinpin"; //$NON-NLS-1$
		final String can = "123456"; //$NON-NLS-1$
		final String signInfo = wrSign.getDnieData(pin, can);
		System.out.println(signInfo);
		final String dataToSignAsBase64 = "SG9sYSBtdW5kbw=="; //$NON-NLS-1$
		final String signAlgotithm = "SHA512withRSA"; //$NON-NLS-1$
		final String signResult = wrSign.sign(dataToSignAsBase64, signAlgotithm);
		System.out.println();
		System.out.println(signResult);
	}
}
