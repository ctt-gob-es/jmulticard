package es.gob.jmulticard.asn1.icao;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.TlvException;

/** Opciones de seguridad de un eMRTD contenidos en el DG14.
 * B&aacute;sicamente es un TLV en cuyos datos encontramos la siguiente
 * estructura ASN&#46;1:<br>
 * <pre>
 *   SecurityInfos ::= SET of SecurityInfo
 *   SecurityInfo ::= SEQUENCE {
 *     protocol OBJECT IDENTIFIER,
 *     requiredData ANY DEFINED BY protocol,
 *     optionalData ANY DEFINED BY protocol OPTIONAL
 *   }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SecurityOptions extends DecoderObject {

	private static final byte TAG = 0x6E;

	@Override
	protected void decodeValue() throws Asn1Exception, TlvException {
		checkTag(getBytes()[0]);
	}

	@Override
	protected byte getDefaultTag() {
		return TAG;
	}

	@Override
	public String toString() {
		return HexUtils.hexify(getBytes(), true);
	}
}
