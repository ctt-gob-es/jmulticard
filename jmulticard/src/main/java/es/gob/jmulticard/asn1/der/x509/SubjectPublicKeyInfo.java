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
 *    algorithm ALGORITHM.&amp;id({IOSet}),
 *    parameters ALGORITHM.&amp;Type({IOSet}{&#64;algorithm}) OPTIONAL
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

	/** Obtiene el campo <code>SubjectPublicKey</code> en su representaci&oacute;n binaria directa.
	 * @return <code>SubjectPublicKey</code>. */
	public byte[] getSubjectPublicKey() {
		// Eliminamos el primer octeto (00)
		final byte[] tmp = ((SubjectPublicKey)getElementAt(1)).getValue();
		final byte[] ret = new byte[tmp.length -1];
		System.arraycopy(tmp, 1, ret, 0, ret.length);
		return ret;
	}

}
