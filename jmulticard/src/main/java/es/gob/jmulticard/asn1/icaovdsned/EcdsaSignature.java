package es.gob.jmulticard.asn1.icaovdsned;

import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.DerInteger;
import es.gob.jmulticard.asn1.der.Sequence;

/** Firma ECDSA.
 * <pre>
 *  ECDSASignature ::= SEQUENCE {
 *    r   INTEGER,
 *    s   INTEGER
 *  }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class EcdsaSignature extends Sequence {

	/** Constructor. */
	public EcdsaSignature() {
		super(
			new OptionalDecoderObjectElement(
				DerInteger.class,
				false
			),
			new OptionalDecoderObjectElement(
				DerInteger.class,
				false
			)
		);
	}
}
