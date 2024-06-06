package es.gob.jmulticard.asn1.der.x509;

import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.ObjectIdentifier;
import es.gob.jmulticard.asn1.der.Sequence;

/** Objeto <i>AlgorithmIdentifier</i> ASN&#46;1 de X&#46;509.
 * <pre>
 *   AlgorithmIdentifier { ALGORITHM:IOSet } ::= SEQUENCE {
 *    algorithm ALGORITHM.&amp;id({IOSet}),
 *    parameters ALGORITHM.&amp;Type({IOSet}{&#64;algorithm}) OPTIONAL
 *   }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class AlgorithmIdentifier extends Sequence {

	/** Crea un objeto <i>AlgorithmIdentifier</i> ASN&#46;1 de X&#46;509. */
	public AlgorithmIdentifier() {
		super(
			new OptionalDecoderObjectElement(
				ObjectIdentifier.class,
				false
			),
			new OptionalDecoderObjectElement(
				ObjectIdentifier.class,
				true
			)
		);
	}

	@Override
	public String toString() {
		return getElementAt(0).toString();
	}
}
