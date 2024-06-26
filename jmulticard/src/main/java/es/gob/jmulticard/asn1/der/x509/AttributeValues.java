package es.gob.jmulticard.asn1.der.x509;

import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.GeneralizedTime;
import es.gob.jmulticard.asn1.der.Set;

/** Tipo ASN&#46;1 X&#46;509 <i>AttributeValues</i>.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class AttributeValues extends Set {

	/** Construye un objeto ASN&#46;1 X&#46;509 <i>AttributeValues</i>.
	 *<pre>
	 *   AttributeValues ::= SET OF AttributeValue }
	 *   AttributeValue ::= ANY DEFINED BY AttributeType
	 *</pre>
	 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
	public AttributeValues() {
		super(
			new OptionalDecoderObjectElement(
				GeneralizedTime.class,
				false
			)
		);
	}

	/** Obtiene los valores del atributo.
	 * @return Valores del atributo. */
	public DecoderObject[] getValues() {
		final DecoderObject[] ret = new DecoderObject[getElementCount()];
		for (int i=0; i<getElementCount(); i++) {
			ret[i] = getElementAt(i);
		}
		return ret;
	}

	@Override
    public String toString() {
		final StringBuilder sb = new StringBuilder();
		for (int i=0; i<getElementCount(); i++) {
			sb.append(getElementAt(i).toString());
			sb.append(", "); //$NON-NLS-1$
		}
		final String ret = sb.toString();
		return ret.substring(0, ret.length()-3);
	}
}
