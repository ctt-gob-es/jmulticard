package es.gob.jmulticard.apdu.connection.cwa14890;

/** Cifrador de APDU seg&uacute;n CWA-14890 mediante 3DES y MAC de 8 octetos. */
public class ApduEncrypterDesMac8 extends ApduEncrypterDes {

    /** Longitud de la MAC de las APDU cifradas. */
    private static final byte MAC_LENGTH_8 = 8;

	@Override
	protected int getMacLength() {
		return MAC_LENGTH_8;
	}
}
