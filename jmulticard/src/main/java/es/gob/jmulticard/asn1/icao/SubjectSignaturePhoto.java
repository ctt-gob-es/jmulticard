package es.gob.jmulticard.asn1.icao;

import java.io.IOException;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.TlvException;

/** Foto(s) de la firma o marca habitual del titular de un eMRTD (DG7 en ICAO 9303 parte 10).
 * Solo se soporta un DG7 que contenga una &uacute;ica imagen de firma.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SubjectSignaturePhoto extends DecoderObject {

	private static final byte TAG = 0x67;

	@Override
	protected void decodeValue() throws Asn1Exception, TlvException {
		checkTag(getBytes()[0]);
		//TODO: Analizar bien los TLV
	}

	@Override
	protected byte getDefaultTag() {
		return TAG;
	}

    /** Obtiene la foto de la firma o marca habitual del titular en formato JPEG2000.
     * @return Foto de la firma del titular en formato JPEG2000.
     * @throws IOException Si la imagen no est&aacute; en formato JPEG2000. */
	public byte[] getSubjectSignaturePhotoAsJpeg2k() throws IOException {
		return IcaoUtils.extractJpeg2kImage(getBytes());
	}
}
