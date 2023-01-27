package es.gob.jmulticard.connection;

import java.util.logging.Logger;

/** Protocolo de conexi&oacute;n con la tarjeta.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public enum ApduConnectionProtocol {

    /** T=0. */
    T0,
    /** T=1. */
    T1,
    /** T=CL. */
    TCL,
    /** Cualquiera. */
    ANY;

    @Override
    public String toString() {
        switch (this) {
            case T0:
                return "T=0"; //$NON-NLS-1$
            case T1:
                return "T=1"; //$NON-NLS-1$
            case TCL:
                return "T=CL"; //$NON-NLS-1$
            default:
                return "*"; //$NON-NLS-1$
        }
    }

    /** Obtiene un protocolo de conexi&oacute;n con tarjeta a partir de su nombre.
     * @param name Nombre del protocolo de conexi&oacute;n con la tarjeta.
     * @return Protocolo de conexi&oacute;n con la tarjeta. */
    public static ApduConnectionProtocol getApduConnectionProtocol(final String name) {
    	switch(name) {
    		case "T=1": return T1; //$NON-NLS-1$
    		case "T=0": return T0; //$NON-NLS-1$
    		case "T=CL": return TCL; //$NON-NLS-1$
    		default:
    			Logger.getLogger("es.gob.jmulticard").warning( //$NON-NLS-1$
					"Protocolo desconocido, se devolvera '*': " + name //$NON-NLS-1$
				);
    			return ANY;
    	}
    }
}
