package es.gob.jmulticard.card.icao;

import es.gob.jmulticard.apdu.Apdu;
import es.gob.jmulticard.apdu.StatusWord;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;

/** Excepci&oacute;n relativa a las funcionalidades ICAO MRTD.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class IcaoException extends Iso7816FourCardException {

	private static final long serialVersionUID = -4567446645471517825L;

	/** Crea una excepci&oacute;n relativa a las funcionalidades ICAO MRTD.
	 * @param retCode Palabra de estado.
     * @param origin APDU que gener&oacute; la palabra de estado.
     * @param description Descripci&oacute;n de la excepci&oacute;n. */
	public IcaoException(final StatusWord retCode, final Apdu origin, final String description) {
		super(retCode, origin, description);
	}

    /** Crea una excepci&oacute;n relativa a las funcionalidades ICAO MRTD.
     * @param description Descripci&oacute;n de la excepci&oacute;n.
     * @param e Excepci&oacute;n de origen. */
	public IcaoException(final String description, final Throwable e) {
		super(description, e);
	}

    /** Crea una excepci&oacute;n relativa a las funcionalidades ICAO MRTD.
     * @param description Descripci&oacute;n de la excepci&oacute;n. */
	public IcaoException(final String description) {
		super(description);
	}
}
