package es.gob.jmulticard.asn1.der.x509;

import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.Sequence;

/** Objeto <code>SubjectPublicKeyInfo</code> de X&#46;509.
 * <pre>
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *    algorithm AlgorithmIdentifier {{ECPKAlgorithms}} (WITH COMPONENTS {algorithm, parameters}) ,
 *    subjectPublicKey BIT STRING
 *   }
 *
 *   AlgorithmIdentifier { ALGORITHM:IOSet } ::= SEQUENCE {
 *    algorithm ALGORITHM.&id({IOSet}),
 *    parameters ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
 *   }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SubjectPublicKeyInfo extends Sequence {

	/** Crea un objeto <code>SubjectPublicKeyInfo</code> de X&#46;509. */
	public SubjectPublicKeyInfo() {
		super(
			new OptionalDecoderObjectElement[] {
				new OptionalDecoderObjectElement(
					AlgorithmIdentifier.class,
					false
				),
				new OptionalDecoderObjectElement(
					SubjectPublicKey.class,
					false
				)
			}
		);
	}

	/** Obtiene el campo <code>SubjectPubicKey</code> en su representaci&oacute;n binaria directa.
	 * @return <code>SubjectPubicKey</code>. */
	public byte[] getSubjectPubicKey() {
		// Eliminamos el primer octeto (00)
		final byte[] tmp = ((SubjectPublicKey)getElementAt(1)).getValue();
		final byte[] ret = new byte[tmp.length -1];
		System.arraycopy(tmp, 1, ret, 0, ret.length);
		return ret;
	}

}
