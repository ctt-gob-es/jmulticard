package es.gob.jmulticard.asn1.icao;

import java.io.IOException;

import es.gob.jmulticard.HexUtils;

/** Utilidades de uso en las estructuras ICAO eMRTD.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class IcaoUtils {

    private static final String JPEG2K_HEADER = "0000000C6A502020"; //$NON-NLS-1$
    private static final String JFIF_HEADER = "FFD8FFE000104A464946"; //$NON-NLS-1$

	private IcaoUtils() {
		// No instanciable
	}

	/** Extrae una foto en JPEG2000 de los datos proporcionados.
	 * Si hay datos m&aacute;s all&aacute;s de la cabecera JPEG2K estos no se detectan,
	 * por lo que la foto puede contener octetos innecesarios al final (que normalmente
	 * no afectan a la correcta lectura de la foto en la mayor&iacute;a de los sistemas).
	 * @param photo Datos que contienen una foto en formato JPEG2000.
	 * @return Foto en formato JPEG2000 (su codificaci&oacute;n binaria).
	 * @throws IOException Si la imagen no est&aacute; en el formato indicado. */
    static byte[] extractJpeg2kImage(final byte[] photo) throws IOException {
    	return extractImage(photo, JPEG2K_HEADER);
    }

	/** Extrae una foto en JFIF de los datos proporcionados.
	 * Si hay datos m&aacute;s all&aacute;s de la foto, estos no se detectan,
	 * por lo que la foto puede contener octetos innecesarios al final (que normalmente
	 * no afectan a la correcta lectura de la foto en la mayor&iacute;a de los sistemas).
	 * @param photo Datos que contienen una foto en formato JFIF.
	 * @return Foto en formato JFIF (su codificaci&oacute;n binaria).
	 * @throws IOException Si la imagen no est&aacute; en el formato indicado. */
    static byte[] extractJfifImage(final byte[] photo) throws IOException {
    	return extractImage(photo, JFIF_HEADER);
    }

	/** Extrae una foto de los datos proporcionados.
	 * Si hay datos m&aacute;s all&aacute;s del final de la imagen estos no se detectan,
	 * por lo que la foto puede contener octetos innecesarios al final (que normalmente
	 * no afectan a la correcta lectura de la foto en la mayor&iacute;a de los sistemas).
	 * @param photo Datos que contienen una foto.
	 * @param magic Cabecera del formato de imagen a extraer.
	 * @return Foto extra&iacute;da (su codificaci&oacute;n binaria).
	 * @throws IOException Si la imagen no est&aacute; en el formato indicado. */
    private static byte[] extractImage(final byte[] photo, final String magic) throws IOException {
    	if (photo == null) {
    		throw new IllegalArgumentException(
				"Los datos de entrada no pueden ser nulos" //$NON-NLS-1$
			);
    	}
    	final int headerIndex = HexUtils.hexify(photo, false).indexOf(magic);
    	if (headerIndex == -1) {
    		throw new IOException(
				"Los datos de entrada no contienen una foto en el formato indicado" //$NON-NLS-1$
			);
    	}
    	final int headerSize = headerIndex / 2;
    	final byte[] photoBytes = new byte[photo.length - headerSize];
        System.arraycopy(photo, headerSize, photoBytes, 0, photoBytes.length);

        // En este punto pj2kPhoto contiene la imagen en el formato indicado
        return photoBytes;
    }
}
