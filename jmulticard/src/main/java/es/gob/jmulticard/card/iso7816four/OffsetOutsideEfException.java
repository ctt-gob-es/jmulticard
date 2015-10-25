package es.gob.jmulticard.card.iso7816four;

import es.gob.jmulticard.apdu.Apdu;
import es.gob.jmulticard.apdu.StatusWord;

/** Indica que se han indicado desplazamientos o tama&ntilde;os de lectura que caen
 * fuera de los l&iacute;mites del fichero.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class OffsetOutsideEfException extends Iso7816FourCardException {

	private static final long serialVersionUID = 1900557624644154869L;

	OffsetOutsideEfException(final StatusWord retCode, final Apdu origin) {
		super(retCode, origin);
	}
}