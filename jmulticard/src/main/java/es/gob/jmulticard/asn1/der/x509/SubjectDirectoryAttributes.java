package es.gob.jmulticard.asn1.der.x509;

import java.util.Date;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.GeneralizedTime;
import es.gob.jmulticard.asn1.der.OctectString;
import es.gob.jmulticard.asn1.der.Sequence;

/** Tipo ASN&#46;1 X&#46;509 <i>SubjectDirectoryAttributes</i>.
 * <pre>
 *   SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
 *   Attribute ::= SEQUENCE {
 *     type AttributeType
 *     values SET OF AttributeValue }
 *   AttributeType ::= OBJECT IDENTIFIER
 *   AttributeValue ::= ANY DEFINED BY AttributeType
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class SubjectDirectoryAttributes extends Sequence {

	/** Construye un objeto ASN&#46;1 X&#46;509 <i>SubjectDirectoryAttributes</i>. */
	public SubjectDirectoryAttributes() {
		super(
			new OptionalDecoderObjectElement(
				Attribute.class,
				false
			)
		);
	}

	@Override
	public void setDerValue(final byte[] byteValue) throws Asn1Exception, TlvException {
		final OctectString os = new OctectString();
		os.setDerValue(byteValue);
		super.setDerValue(os.getOctectStringByteValue());
	}

	@Override
    public String toString() {
		return getElementAt(0).toString();
	}

	/** Obtiene la fecha de nacimiento del titular del certificado.
     * @return Fecha de nacimiento del titular del certificado.
     * @throws Asn1Exception Si la fecha no est&aacute; en el formato esperado. */
    public Date getSubjectBirthDate() throws Asn1Exception {
    	return ((GeneralizedTime)((Attribute)getElementAt(0)).getAttributeValues().getElementAt(0)).getDateValue();
    }
}
