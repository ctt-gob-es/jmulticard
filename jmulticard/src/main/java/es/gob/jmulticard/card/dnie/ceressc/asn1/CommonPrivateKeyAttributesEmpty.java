package es.gob.jmulticard.card.dnie.ceressc.asn1;

import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.DecoderObject;
import es.gob.jmulticard.asn1.TlvException;

/** Tipo ASN&#46;1 PKCS#15 <i>CommonPrivateKeyAttributesEmpty</i>.
 * <pre>
 *  CommonPrivateKeyAttributesEmpty ::= SEQUENCE {
 *    name Name OPTIONAL,
 *    keyIdentifiers [0] SEQUENCE OF CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
 *    generalName [1] GeneralNames OPTIONAL,
 *    ... -- For future extensions
 *  }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CommonPrivateKeyAttributesEmpty extends DecoderObject {

	/** Construye un tipo ASN&#46;1 PKCS#15 <i>CommonPrivateKeyAttributesEmpty</i>. */
	public CommonPrivateKeyAttributesEmpty() {
		super();
	}

	@Override
	protected void decodeValue() throws Asn1Exception, TlvException {
		// vacio
	}

	@Override
	protected byte getDefaultTag() {
		return (byte) 0xff;
	}

}
