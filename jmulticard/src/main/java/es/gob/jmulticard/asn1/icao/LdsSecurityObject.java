package es.gob.jmulticard.asn1.icao;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.DerInteger;
import es.gob.jmulticard.asn1.der.Sequence;
import es.gob.jmulticard.asn1.der.x509.AlgorithmIdentifier;

/** <code>LDSSecurityObject</code> de ICAO MRTD.
 * <pre>
 *	LDSSecurityObject ::= SEQUENCE {
 *     version                LDSSecurityObjectVersion,
 *     hashAlgorithm          DigestAlgorithmIdentifier,
 *     dataGroupHashValues    SEQUENCE SIZE (2..ub-DataGroups) OF DataHashGroup,
 *     ldsVersionInfo         LDSVersionInfo OPTIONAL
 *     -- if present, version MUST be v1
 *	 }
 *
 *	 DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 *	 LDSSecurityObjectVersion :: INTEGER {V0(0)}
 *
 *   AlgorithmIdentifier ::= SEQUENCE {
 *      algorithm OBJECT IDENTIFIER,
 *      parameters ANY DEFINED BY algorithm OPTIONAL
 *   }
 *
 *   LDSVersionInfo ::= SEQUENCE {
 *      ldsVersion PRINTABLE STRING unicodeVersion PRINTABLE STRING
 *   }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class LdsSecurityObject extends Sequence {

	/** Constructor. */
	public LdsSecurityObject() {
		super(
			new OptionalDecoderObjectElement(
				DerInteger.class,          // LDSSecurityObjectVersion
				false
			),
			new OptionalDecoderObjectElement(
				AlgorithmIdentifier.class, // DigestAlgorithmIdentifier
				false
			),
			new OptionalDecoderObjectElement(
				DataGroupHashValues.class, // SEQUENCE SIZE OF DataHashGroup
				false
			),
			new OptionalDecoderObjectElement(
				Sequence.class,            // LDSVersionInfo
				true // Opcional
			)
		);
	}

	@Override
	public String toString() {
		final StringBuilder ret = new StringBuilder("LDSSecurityObject V"); //$NON-NLS-1$
		ret.append(getElementAt(0));
		ret.append(" con huellas para el algoritmo "); //$NON-NLS-1$
		ret.append(getElementAt(1));
		ret.append(" y con el siguiente contenido:"); //$NON-NLS-1$

		final DataGroupHashValues dghv = (DataGroupHashValues) getElementAt(2);
		for (final DataGroupHash dgh : dghv.getDataGroupsHashes()) {
			ret.append("\n  DG"); //$NON-NLS-1$
			ret.append(dgh.getDataGroupNumber());
			ret.append(" con huella "); //$NON-NLS-1$
			ret.append(HexUtils.hexify(dgh.getDataGroupHashValue(), false));
		}
		return ret.toString();
	}

	/** Obtiene el algoritmo de huella com&uacute;n a todos los objetos del
	 * <code>LDSSecurityObject</code>.
	 * @return Nombre del algoritmo de huella. */
	public String getDigestAlgorithm() {
		return getElementAt(1).toString();
	}

	/** Obtiene los <code>DataGroupHash</code> de este <code>LDSSecurityObject</code>.
	 * @return Array de <code>DataGroupHash</code>. */
	public DataGroupHash[] getDataGroupHashes() {
		return ((DataGroupHashValues) getElementAt(2)).getDataGroupsHashes();
	}

}
