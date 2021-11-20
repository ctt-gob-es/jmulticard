package es.gob.jmulticard.asn1.icao;

import es.gob.jmulticard.HexUtils;

/** Utilidades de uso en las estructuras ICAO eMRTD.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class IcaoUtils {

    private static final String JPEG2K_HEADER = "0000000C6A502020"; //$NON-NLS-1$

	private IcaoUtils() {
		// No instanciable
	}

	/** Extrae una foto en JPEG2000 de los datos proporcionados.
	 * Si hay datos m&aacute;s all&aacute;s de la cabecera JPEG2K estos no se detectan,
	 * por lo que la foto puede contener octetos innecesarios al final (que normalmente
	 * no afectan a la correcta lectura de la foto en la mayor&iacute;a de los sistemas).
	 * @param photo Datos que contienen una foto en formato JPEG2000.
	 * @return Foto en formato JPEG2000 (su codificaci&oacute;n binaria). */
    static byte[] extractImage(final byte[] photo) {
    	if (photo == null) {
    		throw new IllegalArgumentException(
				"Los datos de entrada no pueden ser nulos" //$NON-NLS-1$
			);
    	}
    	final int headerIndex = HexUtils.hexify(photo, false).indexOf(JPEG2K_HEADER);
    	if (headerIndex == -1) {
    		throw new IllegalArgumentException(
				"Los datos de entrada no contienen una foto en JPEG2000" //$NON-NLS-1$
			);
    	}
    	final int headerSize = headerIndex / 2;
    	final byte[] pj2kPhoto = new byte[photo.length - headerSize];
        System.arraycopy(photo, headerSize, pj2kPhoto, 0, pj2kPhoto.length);

        // En este punto pj2kPhoto contiene la imagen en JPEG2000
        return pj2kPhoto;
    }

}
