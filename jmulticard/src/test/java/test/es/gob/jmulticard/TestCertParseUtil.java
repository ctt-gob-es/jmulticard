package test.es.gob.jmulticard;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.logging.Logger;

import org.junit.Test;

/** Pruebas de an&aacute;lisis del certificado del DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestCertParseUtil {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	/** Pruebas de la obtenci&oacute;n de nombre y apellidos.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testGetFields() throws Exception {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		final X509Certificate c;
		try (final InputStream is = TestCertParseUtil.class.getResourceAsStream("/DNICERT.cer")) { //$NON-NLS-1$
			c = (X509Certificate) cf.generateCertificate(is);
		}
		final String dn = c.getSubjectDN().toString();
		String cn = getCN(dn);
		if (cn.contains("(")) { //$NON-NLS-1$
			cn = cn.substring(
				0,
				cn.indexOf('(')
			).trim();
		}
		System.out.println(dn);
		System.out.println(cn);

		final String name = cn.substring(
			cn.indexOf(',') + 1
		).trim();
		System.out.println("Nombre: " + //$NON-NLS-1$
			name
		);

		String sn1 = getRDNvalueFromLdapName("SN", dn); //$NON-NLS-1$
		if (sn1 == null) {
			sn1 = getRDNvalueFromLdapName("SURNAME", dn); //$NON-NLS-1$
		}
		System.out.println("Apellido 1: " + sn1); //$NON-NLS-1$

		final String sn2 = cn.replace(",", "").replace(name, "").replace(sn1, "").trim(); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		System.out.println("Apellido 2: " + sn2); //$NON-NLS-1$

		final String num = getRDNvalueFromLdapName("SERIALNUMBER", dn); //$NON-NLS-1$
		System.out.println("Numero: " + num); //$NON-NLS-1$
	}

    /** Obtiene el nombre com&uacute;n (Common Name, CN) de un <i>Principal</i>
     * X.400. Si no se encuentra el CN, se devuelve la unidad organizativa
     * (Organization Unit, OU).
     * @param principal
     *        <i>Principal</i> del cual queremos obtener el nombre
     *        com&uacute;n
     * @return Nombre com&uacute;n (Common Name, CN) de un <i>Principal</i>
     *         X.400 */
    public static String getCN(final String principal) {
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
    public static String getRDNvalueFromLdapName(final String rdn, final String principal) {

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
			if (principal.charAt(offset1) != '"') {
                offset2 = principal.indexOf(',', offset1);
                if (offset2 != -1) {
                    return principal.substring(offset1, offset2).trim();
                }
                return principal.substring(offset1).trim();
            }
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

        return null;
    }

}
