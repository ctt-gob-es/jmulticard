package es.gob.jmulticard.card.dnie;

import java.security.cert.X509Certificate;
import java.util.Locale;

import es.gob.jmulticard.JmcLogger;

/** Utilidad para el an&aacute;lisis de los campos personales del certificado DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class DnieCertParseUtil {

	/* TODO: Soportar fecha de nacimiento, lugar de nacimiento y sexo desde el "Subject Directory Attributes":
	    id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 }
	    SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute   */

	private final String name;
	private String sn1;
	private final String sn2;
	private final String num;

	/** Construye la utilidad para el an&aacute;lisis de los campos personales del certificado DNIe.
	 * @param c Certificado de DNIe. */
	public DnieCertParseUtil(final X509Certificate c) {
		if (c == null) {
			throw new IllegalArgumentException("El certificado no puede ser nulo"); //$NON-NLS-1$
		}
		final String dn = c.getSubjectX500Principal().toString();
		String cn = getCN(dn);
		if (cn.contains("(")) { //$NON-NLS-1$
			cn = cn.substring(0, cn.indexOf('(')).trim();
		}
		name = cn.substring(cn.indexOf(',') + 1).trim();
		sn1 = getRdnValueFromLdapName("SN", dn); //$NON-NLS-1$
		if (sn1 == null) {
			sn1 = getRdnValueFromLdapName("SURNAME", dn); //$NON-NLS-1$
		}
		if (sn1 == null) {
			// Forma del DN en Android
            sn1 = getRdnValueFromLdapName("OID.2.5.4.4", dn); //$NON-NLS-1$
        }
        if (sn1 == null) {
            sn1 = getRdnValueFromLdapName("2.5.4.4", dn); //$NON-NLS-1$
        }
		sn2 = cn.replace(",", "").replace(name, "").replace(sn1, "").trim(); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		num = getRdnValueFromLdapName("SERIALNUMBER", dn); //$NON-NLS-1$
	}

	/** Obtiene el nombre del titular del DNIe.
	 * @return Nombre del titular del DNIe. */
	public String getName() {
		return name;
	}

	/** Obtiene el primer apellido del titular del DNIe.
	 * @return Primer apellido del titular del DNIe. */
	public String getSurname1() {
		return sn1;
	}

	/** Obtiene el segundo apellido del titular del DNIe.
	 * @return Segundo apellido del titular del DNIe. */
	public String getSurname2() {
		return sn2;
	}

	/** Obtiene el n&uacute;mero del DNIe.
	 * @return N&uacute;mero del DNIe. */
	public String getNumber() {
		return num;
	}

    /** Obtiene el nombre com&uacute;n (Common Name, CN) de un <i>Principal</i> X&#46;400.
     * Si no se encuentra el CN, se devuelve la unidad organizativa (Organization Unit, OU).
     * @param principal <i>Principal</i> del cual queremos obtener el nombre com&uacute;n
     * @return Nombre com&uacute;n (Common Name, CN) de un <i>Principal</i> X&#46;400. */
    private static String getCN(final String principal) {
        if (principal == null) {
            return null;
        }

        String rdn = getRdnValueFromLdapName("cn", principal); //$NON-NLS-1$
        if (rdn == null) {
            rdn = getRdnValueFromLdapName("ou", principal); //$NON-NLS-1$
        }

        if (rdn != null) {
            return rdn;
        }

        final int i = principal.indexOf('=');
        if (i != -1) {
        	JmcLogger.warning(
        		"No se ha podido obtener el CN ni la OU, se devolvera el fragmento mas significativo" //$NON-NLS-1$
    		);
            return getRdnValueFromLdapName(principal.substring(0, i), principal);
        }

        JmcLogger.warning("Principal no valido, se devolvera el valor de entrada"); //$NON-NLS-1$
        return principal;
    }

	@Override
	public String toString() {
		return
			"Nombre: "           + name + "\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"Primer apellido: "  + sn1  + "\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"Segundo apellido: " + sn2  + "\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"Numero: "           + num; //$NON-NLS-1$
	}

    /** Recupera el valor de un RDN (<i>Relative Distinguished Name</i>) de un principal.
     * El valor de retorno no incluye el nombre del RDN, el igual, ni las posibles comillas que envuelvan el valor.
     * La funci&oacute;n no es sensible a la capitalizaci&oacute;n del RDN.
     * Si no se encuentra, se devuelve {@code null}.
     * @param rdn RDN que deseamos encontrar.
     * @param principal Principal del que extraer el RDN (seg&uacute;n la <a href="http://www.ietf.org/rfc/rfc4514.txt">RFC 4514</a>).
     * @return Valor del RDN indicado o {@code null} si no se encuentra. */
    private static String getRdnValueFromLdapName(final String rdn, final String principal) {

        int offset1 = 0;
        while ((offset1 = principal.toLowerCase(Locale.US).indexOf(rdn.toLowerCase(), offset1)) != -1) {

            if (offset1 > 0 && principal.charAt(offset1-1) != ',' && principal.charAt(offset1-1) != ' ') {
                offset1++;
                continue;
            }

            offset1 += rdn.length();
            while (offset1 < principal.length() && principal.charAt(offset1) == ' ') {
                offset1++;
            }

            if (offset1 >= principal.length()) {
                return null;
            }

            if (principal.charAt(offset1) != '=') {
                continue;
            }

            offset1++;
            while (offset1 < principal.length() && principal.charAt(offset1) == ' ') {
                offset1++;
            }

            if (offset1 >= principal.length()) {
                return ""; //$NON-NLS-1$
            }

            int offset2;
            if (principal.charAt(offset1) == ',') {
                return ""; //$NON-NLS-1$
            }
			if (principal.charAt(offset1) == '"') {
                offset1++;
                if (offset1 >= principal.length()) {
                    return ""; //$NON-NLS-1$
                }

                offset2 = principal.indexOf('"', offset1);
                if (offset2 == offset1) {
                    return ""; //$NON-NLS-1$
                }
				if (offset2 != -1) {
                    return principal.substring(offset1, offset2);
                }
				return principal.substring(offset1);
            }
			offset2 = principal.indexOf(',', offset1);
			if (offset2 != -1) {
			    return principal.substring(offset1, offset2).trim();
			}
			return principal.substring(offset1).trim();
        }

        return null;
    }
}
