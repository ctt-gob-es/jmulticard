package es.gob.jmulticard.apdu.connection;

/** Protocolo de conexi&oacute;n con la tarjeta.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
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
}
