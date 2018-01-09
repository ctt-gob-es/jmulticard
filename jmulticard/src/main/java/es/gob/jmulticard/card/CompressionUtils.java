package es.gob.jmulticard.card;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/** Utilidades de compresi&oacute;n de certificados seg&uacute;n uso com&uacute;n en
 * tarjetas FNMT.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CompressionUtils {

	private CompressionUtils() {
		// No instanciable
	}

    /** Descomprime un certificado.
     * @param compressedCertificate Certificado comprimido en ZIP a partir del 9 octeto.
     * @return Certificado codificado.
     * @throws IOException Cuando se produce un error en la descompresi&oacute;n del certificado. */
    public static byte[] deflate(final byte[] compressedCertificate) throws IOException {
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        final Inflater decompressor = new Inflater();
        decompressor.setInput(compressedCertificate, 8, compressedCertificate.length - 8);
        final byte[] buf = new byte[1024];
        try {
            // Descomprimimos los datos
            while (!decompressor.finished()) {
                final int count = decompressor.inflate(buf);
                if (count == 0) {
                    throw new DataFormatException();
                }
                buffer.write(buf, 0, count);
            }
            // Obtenemos los datos descomprimidos
            return buffer.toByteArray();
        }
        catch (final DataFormatException ex) {
            throw new IOException("Error al descomprimir el certificado: " + ex, ex); //$NON-NLS-1$
        }
    }

}
