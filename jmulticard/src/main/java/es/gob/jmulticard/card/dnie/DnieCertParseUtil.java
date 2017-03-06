package es.gob.jmulticard.card.dnie;

import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.logging.Logger;

/** Utilidad para el an&aacute;lisis de los campos personales del certificado DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class DnieCertParseUtil {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	private final String name;
	private String sn1;
	private final String sn2;
	private final String num;

	/** Construye la utilidad para el an&aacute;lisis de los campos personales del certificado DNIe.
	 * @param c Certificado de DNIe. */
	public DnieCertParseUtil(final X509Certificate c) {
		if (c == null) {
			throw new IllegalArgumentException(
				"El certificado no puede ser nulo" //$NON-NLS-1$
			);
		}
		final String dn = c.getSubjectDN().toString();
		String cn = getCN(dn);
		if (cn.contains("(")) { //$NON-NLS-1$
			cn = cn.substring(
				0,
				cn.indexOf('(')
			).trim();
		}
		this.name = cn.substring(
			cn.indexOf(',') + 1,
			cn.length()
		).trim();
		this.sn1 = getRDNvalueFromLdapName("SN", dn); //$NON-NLS-1$
		if (this.sn1 == null) {
			this.sn1 = getRDNvalueFromLdapName("SURNAME", dn); //$NON-NLS-1$
		}
		this.sn2 = cn.replace(",", "").replace(this.name, "").replace(this.sn1, "").trim(); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		this.num = getRDNvalueFromLdapName("SERIALNUMBER", dn); //$NON-NLS-1$
	}

	/** Obtiene el nombre del titular del DNIe.
	 * @return Nombre del titular del DNIe. */
	public String getName() {
		return this.name;
	}

	/** Obtiene el primer apellido del titular del DNIe.
	 * @return Primer apellido del titular del DNIe. */
	public String getSurname1() {
		return this.sn1;
	}

	/** Obtiene el segundo apellido del titular del DNIe.
	 * @return Segundo apellido del titular del DNIe. */
	public String getSurname2() {
		return this.sn2;
	}

	/** Obtiene el n&uacute;mero del DNIe.
	 * @return N&uacute;mero del DNIe. */
	public String getNumber() {
		return this.num;
	}

    /** Obtiene el nombre com&uacute;n (Common Name, CN) de un <i>Principal</i>
     * X.400. Si no se encuentra el CN, se devuelve la unidad organizativa
     * (Organization Unit, OU).
     * @param principal
     *        <i>Principal</i> del cual queremos obtener el nombre
     *        com&uacute;n
     * @return Nombre com&uacute;n (Common Name, CN) de un <i>Principal</i>
     *         X.400 */
    private static String getCN(final String principal) {
        if (principal == null) {
            return null;
        }

        String rdn = getRDNvalueFromLdapName("cn", principal); //$NON-NLS-1$
        if (rdn == null) {
            rdn = getRDNvalueFromLdapName("ou", principal); //$NON-NLS-1$
        }

        if (rdn != null) {
            return rdn;
        }

        final int i = principal.indexOf('=');
        if (i != -1) {
            LOGGER.warning("No se ha podido obtener el Common Name ni la Organizational Unit, se devolvera el fragmento mas significativo"); //$NON-NLS-1$
            return getRDNvalueFromLdapName(principal.substring(0, i), principal);
        }

        LOGGER.warning("Principal no valido, se devolvera la entrada"); //$NON-NLS-1$
        return principal;
    }

    /** Recupera el valor de un RDN (<i>Relative Distinguished Name</i>) de un principal. El valor de retorno no incluye
     * el nombre del RDN, el igual, ni las posibles comillas que envuelvan el valor.
     * La funci&oacute;n no es sensible a la capitalizaci&oacute;n del RDN. Si no se
     * encuentra, se devuelve {@code null}.
     * @param rdn RDN que deseamos encontrar.
     * @param principal Principal del que extraer el RDN (seg&uacute;n la <a href="http://www.ietf.org/rfc/rfc4514.txt">RFC 4514</a>).
     * @return Valor del RDN indicado o {@code null} si no se encuentra. */
    private static String getRDNvalueFromLdapName(final String rdn, final String principal) {

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
            else if (principal.charAt(offset1) == '"') {
                offset1++;
                if (offset1 >= principal.length()) {
                    return ""; //$NON-NLS-1$
                }

                offset2 = principal.indexOf('"', offset1);
                if (offset2 == offset1) {
                    return ""; //$NON-NLS-1$
                }
                else if (offset2 != -1) {
                    return principal.substring(offset1, offset2);
                }
                else {
                    return principal.substring(offset1);
                }
            }
            else {
                offset2 = principal.indexOf(',', offset1);
                if (offset2 != -1) {
                    return principal.substring(offset1, offset2).trim();
                }
                return principal.substring(offset1).trim();
            }
        }

        return null;
    }

}
