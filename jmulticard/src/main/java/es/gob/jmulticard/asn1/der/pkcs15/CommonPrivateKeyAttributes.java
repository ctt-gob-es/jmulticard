package es.gob.jmulticard.asn1.der.pkcs15;

import javax.security.auth.x500.X500Principal;

import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.der.Sequence;
import es.gob.jmulticard.asn1.der.x509.RdnSequence;

/** Tipo ASN&#46;1 PKCS#15 <i>CommonPrivateKeyAttributes</i>.
 * <pre>
 *  CommonPrivateKeyAttributes ::= SEQUENCE {
 *    name Name OPTIONAL,
 *    keyIdentifiers [0] SEQUENCE OF CredentialIdentifier {{KeyIdentifiers}} OPTIONAL,
 *    generalName [1] GeneralNames OPTIONAL,
 *    ... -- For future extensions
 *  }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CommonPrivateKeyAttributes extends Sequence {

	/** Construye un tipo ASN&#46;1 PKCS#15 <i>CommonPrivateKeyAttributes</i>. */
	public CommonPrivateKeyAttributes() {
		super(
			// Solo contemplamos el "name", que es de tipo "Name",
			// implementado casi siempre como "RdnSequence".
			new OptionalDecoderObjectElement[] {
				new OptionalDecoderObjectElement(
					RdnSequence.class,
					true // Opcional
				)
			}
		);
	}

	/** Obtiene el <code>Principal</code> X&#46;509 de la clave privada.
	 * @return <code>Principal</code> X&#46;509 de la clave privada. */
	public X500Principal getKeyPrincipal() {
		for (int i=0;i<getElementCount();i++) {
			final Object o = getElementAt(i);
			if (o instanceof RdnSequence) {
				return ((RdnSequence)o).getKeyprincipal();
			}
		}
		return null;
	}

}
