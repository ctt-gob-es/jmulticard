package es.gob.jmulticard.card;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import es.gob.jmulticard.CertificateUtils;

/** Utilidades de compresi&oacute;n de certificados seg&uacute;n uso com&uacute;n en
 * tarjetas FNMT.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CompressionUtils {

	/** Registro. */
	protected static final Logger LOGGER = Logger.getLogger("es.gob.jmulticard"); //$NON-NLS-1$

	/** Constructor privado y vac&iacute;o. */
	private CompressionUtils() {
		// No instanciable
	}

	/** Obtiene un certificado a partir de unos datos que pueden ser, o bien el propio certificado
	 * X&#46;509 o la codificaci&oacute;n de este comprmida seg&uacute;n esquema FNMT.
	 * De utilidad en todas las tarjetas FNMT-RCM, incluyendo DNIe.
	 * @param data Datos del certificado, que pueden estar comprimidos o no.
	 * @return Certificado X&#46;509.
	 * @throws IOException Si no pueden leerse los datos.
	 * @throws CertificateException Si los datos no son, ni comprimidos ni descomprimidos, un
	 *                              certificado X&#46;509. */
	public static X509Certificate getCertificateFromCompressedOrNotData(final byte[] data) throws IOException,
	                                                                                              CertificateException {
		if (data == null || data.length < 1) {
			throw new IOException("Los datos del certificado eran nulos o vacios"); //$NON-NLS-1$
		}
		byte[] rawData;
		try {
    		rawData = CompressionUtils.deflate(
				data
			);
		}
        catch(final Exception e) {
        	LOGGER.warning(
    			"Ha fallado la descompresion del certificado, se probara sin descomprimir: " + e //$NON-NLS-1$
			);
        	rawData = data;
        }
		return CertificateUtils.generateCertificate(rawData);
	}

    /** Descomprime un certificado.
     * @param compressedCertificate Certificado comprimido en ZIP a partir del 9 octeto.
     * @return Certificado codificado.
     * @throws IOException Cuando se produce un error en la descompresi&oacute;n del certificado. */
    private static byte[] deflate(final byte[] compressedCertificate) throws IOException {
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
