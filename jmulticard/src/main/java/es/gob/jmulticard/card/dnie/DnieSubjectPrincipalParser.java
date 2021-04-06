package es.gob.jmulticard.card.dnie;

import java.util.Locale;

/** Analizador del nombre X&#46;500 del titular de un DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class DnieSubjectPrincipalParser {

	private final String name;
	private final String surname1;
	private final String surname2;
	private final String id;


	/** Construye un nalizador del nombre X&#46;500 del titular de un DNIe.
	 * @param subjectPrincipal Nombre X&#46;500 del titular. */
	public DnieSubjectPrincipalParser(final String subjectPrincipal) {
		this.name = getRDNvalueFromLdapName("GIVENNAME", subjectPrincipal); //$NON-NLS-1$
		this.surname1 =  getRDNvalueFromLdapName("SURNAME", subjectPrincipal); //$NON-NLS-1$
		this.surname2 = getRDNvalueFromLdapName("CN", subjectPrincipal) != null ? //$NON-NLS-1$
			getRDNvalueFromLdapName("CN", subjectPrincipal) //$NON-NLS-1$
				.replace("(AUTENTICACI\u00D3N)", "") //$NON-NLS-1$ //$NON-NLS-2$
				.replace("(FIRMA)", "") //$NON-NLS-1$ //$NON-NLS-2$
				.replace(",", "") //$NON-NLS-1$ //$NON-NLS-2$
				.replace(this.name, "") //$NON-NLS-1$
				.replace(this.surname1, "") //$NON-NLS-1$
				.trim():
					null;
		this.id = getRDNvalueFromLdapName("SERIALNUMBER", subjectPrincipal); //$NON-NLS-1$
	}

	/** Obtiene el nombre del titular del DNIe.
	 * @return Nombre del titular del DNIe. */
	public String getName() {
		return this.name;
	}

	/** Obtiene el primer apellido del titular del DNIe.
	 * @return Primer apellido del titular del DNIe. */
	public String getSurname1() {
		return this.surname1;
	}


	/** Obtiene el segundo apellido del titular del DNIe.
	 * @return Segundo apellido del titular del DNIe. */
	public String getSurname2() {
		return this.surname2;
	}

	/** Obtiene el n&uacute;mero del DNIe.
	 * @return N&uacute;mero del DNIe. */
	public String getId() {
		return this.id;
	}

	@Override
	public String toString() {
		return
			"Nombre: " + this.name + "\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"Primer apellido: " + this.surname1 + "\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"Segundo apellido: " + this.surname2 + "\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"Numero: " + this.id; //$NON-NLS-1$
	}

    /** Recupera el valor de un RDN (<i>Relative Distinguished Name</i>) de un principal.
     * El valor de retorno no incluye el nombre del RDN, el igual, ni las posibles comillas
     * que envuelvan el valor.
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
			if (principal.charAt(offset1) == '"') {
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
