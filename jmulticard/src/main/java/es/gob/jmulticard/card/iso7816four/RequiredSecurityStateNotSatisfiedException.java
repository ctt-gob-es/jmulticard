package es.gob.jmulticard.card.iso7816four;

import es.gob.jmulticard.apdu.StatusWord;


/** Error que se produce cuando se intenta realizar una operaci&oacute;n ISO-7816-4 antes
 * de cumplir las precondiciones de seguridad necesarias (por ejemplo, leer las referencias
 * a las claves privadas sin haber antes introducido el PIN).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class RequiredSecurityStateNotSatisfiedException extends Iso7816FourCardException {

	private static final long serialVersionUID = -5145858128531217344L;

	RequiredSecurityStateNotSatisfiedException(final StatusWord retCode) {
		super("Condicion de seguridad no satisfecha", retCode); //$NON-NLS-1$
	}
}
