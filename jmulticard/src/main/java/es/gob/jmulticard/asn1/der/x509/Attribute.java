package es.gob.jmulticard.asn1.der.x509;

import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.ObjectIdentifier;
import es.gob.jmulticard.asn1.der.Sequence;

/** Tipo ASN&#46;1 X&#46;509 <i>Attribute</i>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class Attribute extends Sequence {

	/** Construye un objeto ASN&#46;1 X&#46;509 <i>Attribute</i>.
	 *
	 *<pre>
	 *   Attribute ::= SEQUENCE {
	 *     type AttributeType
	 *     values SET OF AttributeValue }
	 *   AttributeType ::= OBJECT IDENTIFIER
	 *   AttributeValue ::= ANY DEFINED BY AttributeType
	 *</pre>
	 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
	public Attribute() {
		super(
			// Tipo de atributo
			new OptionalDecoderObjectElement(
				ObjectIdentifier.class,
				false
			),
			// Valor del atributo
			new OptionalDecoderObjectElement(
				AttributeValues.class,
				false
			)
		);
	}

	/** Obtiene los valores del atributo.
	 * @return Valores del atributo. */
	public AttributeValues getAttributeValues() {
		return (AttributeValues) getElementAt(1);
	}

	@Override
    public String toString() {
		return getElementAt(0).toString() + " = " + getElementAt(1).toString(); //$NON-NLS-1$
	}
}
