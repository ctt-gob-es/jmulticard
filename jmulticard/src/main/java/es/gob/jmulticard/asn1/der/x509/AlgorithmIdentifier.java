package es.gob.jmulticard.asn1.der.x509;

import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.ObjectIdentifier;
import es.gob.jmulticard.asn1.der.Sequence;

/** Objeto <i>AlgorithmIdentifier</i> ASN&#46;1 de X&#46;509.
 * <pre>
 *   AlgorithmIdentifier { ALGORITHM:IOSet } ::= SEQUENCE {
 *    algorithm ALGORITHM.&id({IOSet}),
 *    parameters ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
 *   }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class AlgorithmIdentifier extends Sequence {

	/** Crea un objeto <i>AlgorithmIdentifier</i> ASN&#46;1 de X&#46;509. */
	public AlgorithmIdentifier() {
		super(
			new OptionalDecoderObjectElement[] {
				new OptionalDecoderObjectElement(
					ObjectIdentifier.class,
					false
				),
				new OptionalDecoderObjectElement(
					ObjectIdentifier.class,
					true
				)
			}
		);
	}

}
