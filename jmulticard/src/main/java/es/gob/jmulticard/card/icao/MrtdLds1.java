package es.gob.jmulticard.card.icao;

import java.io.IOException;
import java.security.cert.X509Certificate;

import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.icao.Com;
import es.gob.jmulticard.asn1.icao.OptionalDetails;
import es.gob.jmulticard.asn1.icao.Sod;
import es.gob.jmulticard.asn1.icao.SodException;
import es.gob.jmulticard.asn1.icao.SubjectFacePhoto;
import es.gob.jmulticard.asn1.icao.SubjectSignaturePhoto;
import es.gob.jmulticard.card.Location;

/** MRTD ICAO LDS1.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public interface MrtdLds1 {

	/** Localizaci&oacute;n del fichero EF.DG1. */
    Location FILE_DG01_LOCATION = new Location("3F010101"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG2. */
    Location FILE_DG02_LOCATION = new Location("3F010102"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG3. */
    Location FILE_DG03_LOCATION = new Location("3F010103"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG4. */
    Location FILE_DG04_LOCATION = new Location("3F010104"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG5. */
    Location FILE_DG05_LOCATION = new Location("3F010105"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG6. */
    Location FILE_DG06_LOCATION = new Location("3F010106"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG7. */
    Location FILE_DG07_LOCATION = new Location("3F010107"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG8. */
    Location FILE_DG08_LOCATION = new Location("3F010108"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG9. */
    Location FILE_DG09_LOCATION = new Location("3F010109"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG10. */
    Location FILE_DG10_LOCATION = new Location("3F01010A"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG11. */
    Location FILE_DG11_LOCATION = new Location("3F01010B"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG12. */
    Location FILE_DG12_LOCATION = new Location("3F01010C"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG13. */
    Location FILE_DG13_LOCATION = new Location("3F01010D"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG14. */
    Location FILE_DG14_LOCATION = new Location("3F01010E"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG15. */
    Location FILE_DG15_LOCATION = new Location("3F01010F"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.DG16. */
    Location FILE_DG16_LOCATION = new Location("3F010110"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.SOD. */
    Location FILE_SOD_LOCATION  = new Location("3F01011D"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.COM. */
    Location FILE_COM_LOCATION  = new Location("3F01011E"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.CardAccess. */
    Location FILE_CARD_ACCESS_LOCATION = new Location("011C"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.ATR/INFO. */
    Location FILE_ATR_INFO_LOCATION = new Location("2F01"); //$NON-NLS-1$

    /** Localizaci&oacute;n del fichero EF.CardSecurity. */
    Location FILE_CARD_SECURITY_LOCATION = new Location("011D"); //$NON-NLS-1$

    /** Obtiene el DG1 (MRZ).
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG1 (MRZ).
     * @throws IOException Si hay problemas leyendo el fichero. */
    Mrz getDg1() throws IOException;

    /** Obtiene el DG2 (fotograf&iacute;a del rostro del titular).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG2 (fotograf&iacute;a del rostro del titular).
     * @throws IOException Si hay problemas leyendo el fichero. */
    SubjectFacePhoto getDg2() throws IOException;

    /** Obtiene el DG3 (Elementos de identificaci&oacute;n adicionales - Dedos).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de administraci&oacute;n est&eacute; previamente establecido.
     * @return DG3 (Elementos de identificaci&oacute;n adicionales - Dedos).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg3() throws IOException;

    /** Obtiene el DG4 (Elementos de identificaci&oacute;n adicionales - Iris).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de administraci&oacute;n est&eacute; previamente establecido.
     * @return DG4 (Elementos de identificaci&oacute;n adicionales - Iris).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg4() throws IOException;

    /** Obtiene el DG5 (Retrato exhibido).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @return DG5 (Retrato exhibido).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg5() throws IOException;

    /** Obtiene el DG6 (Reservado para uso futuro).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @return DG6 (Reservado para uso futuro).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg6() throws IOException;

    /** Obtiene el DG7 (Imagen de la firma o marca habitual exhibida).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG7 (imagen de la firma o marca habitual exhibida).
     * @throws IOException Si hay problemas leyendo el fichero. */
    SubjectSignaturePhoto getDg7() throws IOException;

    /** Obtiene el DG8 (Elemento datos).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @return DG7 (Elemento datos).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg8() throws IOException;

    /** Obtiene el DG9 (Elemento estructura).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @return DG9 (Elemento estructura).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg9() throws IOException;

    /** Obtiene el DG10 (Elemento sustancia).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @return DG10 (Elemento sustancia).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg10() throws IOException;

	/** Obtiene el DG11 (Detalles personales adicionales).
	 * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG11 (Detalles personales adicionales).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg11() throws IOException;

    /** Obtiene el DG12 (Detalles del documento adicionales).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG12 (Detalles del documento adicionales).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg12() throws IOException;

    /** Obtiene el DG13 (Detalles opcionales).
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG13 (Detalles opcionales).
     * @throws IOException Si hay problemas leyendo el fichero. */
    OptionalDetails getDg13() throws IOException;

    /** Obtiene el DG14 (Opciones de seguridad).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG14 (Opciones de seguridad).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg14() throws IOException;

    /** Obtiene el DG15 (Información de clave pública de autenticación activa).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @return DG15 (Información de clave pública de autenticación activa).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg15() throws IOException;

    /** Obtiene el DG16 (Personas que han de notificarse).
     * Devuelve el objeto binario sin tratar.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @return DG16 (Personas que han de notificarse).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg16() throws IOException;

    /** Obtiene el SOD.
     * El SOD contiene las huellas digitales de los DG.
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @return SOD.
     * @throws IOException Si hay problemas obteniendo el objeto. */
    Sod getSod() throws IOException;

    /** Obtiene el COM.
     * El COM contiene los "datos comunes" (<i>Common Data</i>).
     * Puede necesitar que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return COM.
     * @throws IOException Si hay problemas leyendo el fichero. */
    Com getCom() throws IOException;

    /** Obtiene el CardAccess.
     * @return CardAccess.
     * @throws IOException Si no se puede leer el fichero. */
    byte[] getCardAccess() throws IOException;

    /** Obtiene el CardSecurity.
     * @return CardSecurity.
     * @throws IOException Si no se puede leer el fichero. */
    byte[] getCardSecurity() throws IOException;

    /** Obtiene el ATR/INFO.
     * @return ATR/INFO.
     * @throws IOException Si no se puede leer el fichero. */
    byte[] getAtrInfo() throws IOException;

    /** Comprueba la validez de los objetos de seguridad a partir del SOD.
     * @return Cadena de certificados del firmante del SOD (para comprobaci&oacute;n
     *         externa).
     * @throws IOException Si no se puede  finalizar la comprobaci&oacute;n.
     * @throws InvalidSecurityObjectException Si un objeto de seguridad no supera
     *                                        las comprobaciones de seguridad.
     * @throws TlvException Si el SOD del documento no es un TLV v&aacute;lido.
     * @throws SodException Si el SOD es estructuralmente incorrecto. */
    X509Certificate[] checkSecurityObjects() throws IOException, InvalidSecurityObjectException, SodException, TlvException;
}
