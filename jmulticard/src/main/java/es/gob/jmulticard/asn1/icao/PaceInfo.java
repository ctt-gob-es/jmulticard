package es.gob.jmulticard.asn1.icao;

import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.DerInteger;
import es.gob.jmulticard.asn1.der.ObjectIdentifier;
import es.gob.jmulticard.asn1.der.Sequence;

/** <code>PACEInfo</code> de ICAO MRTD.
 * <pre>
 *   PACEInfo ::= SEQUENCE {
 *      protocol OBJECT IDENTIFIER(
 *         id-PACE-DH-GM-3DES-CBC-CBC |
 *         id-PACE-DH-GM-AES-CBC-CMAC-128 |
 *         id-PACE-DH-GM-AES-CBC-CMAC-192 |
 *         id-PACE-DH-GM-AES-CBC-CMAC-256 |
 *         id-PACE-ECDH-GM-3DES-CBC-CBC |
 *         id-PACE-ECDH-GM-AES-CBC-CMAC-128 |
 *         id-PACE-ECDH-GM-AES-CBC-CMAC-192 |
 *         id-PACE-ECDH-GM-AES-CBC-CMAC-256 |
 *         id-PACE-DH-IM-3DES-CBC-CBC |
 *         id-PACE-DH-IM-AES-CBC-CMAC-128 |
 *         id-PACE-DH-IM-AES-CBC-CMAC-192 |
 *         id-PACE-DH-IM-AES-CBC-CMAC-256 |
 *         id-PACE-ECDH-IM-3DES-CBC-CBC |
 *         id-PACE-ECDH-IM-AES-CBC-CMAC-128 |
 *         id-PACE-ECDH-IM-AES-CBC-CMAC-192 |
 *         id-PACE-ECDH-IM-AES-CBC-CMAC-256
 *         id-PACE-ECDH-CAM-AES-CBC-CMAC-128 |
 *         id-PACE-ECDH-CAM-AES-CBC-CMAC-192 |
 *         id-PACE-ECDH-CAM-AES-CBC-CMAC-256),
 *      version INTEGER, -- MUST be 2
 *      parameterId INTEGER OPTIONAL
 *   }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class PaceInfo extends Sequence {

	/** Constructor. */
	public PaceInfo() {
		super(
			new OptionalDecoderObjectElement(
				ObjectIdentifier.class, // protocol
				false
			),
			new OptionalDecoderObjectElement(
				DerInteger.class,       // version
				false
			),
			new OptionalDecoderObjectElement(
				DerInteger.class,       // parameterId
				true // Opcional
			)
		);
	}

	@Override
	public String toString() {
		final StringBuilder ret = new StringBuilder("PACEInfo V"); //$NON-NLS-1$
		ret.append(getElementAt(1));
		ret.append(" para el protocolo "); //$NON-NLS-1$
		ret.append(getElementAt(0));

		if (getElementCount() > 2) {
			ret.append(" y con identificador de parametro "); //$NON-NLS-1$
			ret.append(getElementAt(2));
		}
		return ret.toString();
	}

	/** Obtiene el protocolo de este <code>PACEInfo</code>.
	 * @return Protocolo de este <code>PACEInfo</code>. */
	public String getProtocol() {
		return getElementAt(0).toString();
	}

	/** Obtiene la versi&oacute;n de este <code>PACEInfo</code>.
	 * @return Versi&oacute;n de este <code>PACEInfo</code>. */
	public int getVersion() {
		return ((DerInteger)getElementAt(1)).getIntegerValue().intValue();
	}

	/** Obtiene el identificador del par&aacute;metro.
	 * @return Identificador del par&aacute;metro, o -1 si no se cuenta con ese dato. */
	public int getparameterId() {
		if (getElementCount() > 2) {
			return ((DerInteger)getElementAt(2)).getIntegerValue().intValue();
		}
		return -1;
	}
}
