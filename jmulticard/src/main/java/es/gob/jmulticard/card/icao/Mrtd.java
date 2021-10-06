package es.gob.jmulticard.card.icao;

import java.io.IOException;

/** MRTD ICAO.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public interface Mrtd {

    /** Obtiene el DG1. Devuelve el objeto binario sin tratar.
     * El DG1 contiene el campo MRZ. Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG1 (con el MRZ).
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg1() throws IOException;

    /** Obtiene el DG2. Devuelve el objeto binario sin tratar.
     * El DG2 contiene la fotograf&iacute;a  del documento.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG2.
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg2() throws IOException;

    /** Obtiene el DG7. Devuelve el objeto binario sin tratar.
     * El DG7 contiene la imagen de la firma del poseedor del documento.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG7.
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg7() throws IOException;

	/** Obtiene el DG11. Devuelve el objeto binario sin tratar.
     * El DG11 contiene detalles adicionales sobre el poseedor del documento.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG11.
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg11() throws IOException;

    /** Obtiene el DG12. Devuelve el objeto binario sin tratar.
     * El DG12 contiene datos adicionales del documento.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG12.
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg12() throws IOException;

    /** Obtiene el DG13. Devuelve el objeto binario sin tratar.
     * El DG12 contiene detalles opcionales.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG13.
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg13() throws IOException;

    /** Obtiene el DG14. Devuelve el objeto binario sin tratar.
     * El DG12 contiene opciones de seguridad.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return DG14.
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getDg14() throws IOException;

    /** Obtiene el SOD. Devuelve el objeto binario sin tratar.
     * El SOD contiene las huellas digitales de los DG.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return SOD.
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getSOD() throws IOException;

    /** Obtiene el COM. Devuelve el objeto binario sin tratar.
     * El COM contiene los "datos comunes" (<i>Common Data</i>).
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @author Ignacio Mar&iacute;n.
     * @return COM.
     * @throws IOException Si hay problemas leyendo el fichero. */
    byte[] getCOM() throws IOException;

    /** Obtiene la foto del titular en formato JPEG2000.
     * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @return Foto del titular en formato JPEG2000.
     * @throws IOException Si no se puede leer la foto del titular. */
	byte[] getSubjectPhotoAsJpeg2k() throws IOException;

	/** Obtiene la MRZ del MRTD.
	 * Necesita que el canal de usuario est&eacute; previamente establecido.
	 * @return MRZ del MRTD.
	 * @throws IOException Si no se puede leer el fichero con el MRZ del MRTD. */
	Mrz getMrz() throws IOException;

	/** Obtiene los datos de identidad del titular.
	 * @return Datos de identidad del titular.
	 * @throws IOException Si no se pueden leer los datos de identidad (fichero DG13
	 *                     del MRTD). */
	Dg13Identity getIdentity() throws IOException;

	/** Obtiene la imagen de la firma del titular en formato JPEG2000.
	 * Necesita que el canal de usuario est&eacute; previamente establecido.
     * @return Imagen de la firma del titular en formato JPEG2000.
	 * @throws IOException Si no se puede leer la imagen con la firma del titular. */
	byte[] getSubjectSignatureImageAsJpeg2k() throws IOException;

}
