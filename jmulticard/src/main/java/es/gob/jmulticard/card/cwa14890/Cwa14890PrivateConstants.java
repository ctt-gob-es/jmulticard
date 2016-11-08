package es.gob.jmulticard.card.cwa14890;

import java.security.interfaces.RSAPrivateKey;

/** Gestiona las constantes p&uacute;blicas para el establecimiento de canal seguro CWA-14890.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s.  */
public interface Cwa14890PrivateConstants {

    /** Obtiene la clave privada del certificado de Terminal.
     * @return Clave privada del certificado de Terminal. */
    RSAPrivateKey getIfdPrivateKey();

}
