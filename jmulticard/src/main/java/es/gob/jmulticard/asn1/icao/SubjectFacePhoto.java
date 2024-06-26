package es.gob.jmulticard.asn1.icao;

import java.io.IOException;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.TlvException;

/** Foto(s) de la cara del titular de un eMRTD (DG2 en ICAO 9303 parte 10).
 * Solo se soporta un DG2 que contenga una &uacute;ica foto del rostro.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SubjectFacePhoto extends DecoderObject {

	private static final byte TAG = 0x75;

	@Override
	protected void decodeValue() throws Asn1Exception, TlvException {
		checkTag(getBytes()[0]);
		//TODO: Analizar bien los TLV
	}

	@Override
	protected byte getDefaultTag() {
		return TAG;
	}

    /** Obtiene la foto del titular en formato JPEG2000.
     * @return Foto del titular en formato JPEG2000.
     * @throws IOException Si la imagen del MRTD no est&aacute; en formato JPEG2000. */
	public byte[] getSubjectPhotoAsJpeg2k() throws IOException {
		return IcaoUtils.extractJpeg2kImage(getBytes());
	}
}
