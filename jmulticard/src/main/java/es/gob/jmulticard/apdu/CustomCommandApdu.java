package es.gob.jmulticard.apdu;

public class CustomCommandApdu extends CommandApdu {

	protected CustomCommandApdu(final byte cla, final byte ins, final byte param1, final byte param2,
			final byte[] data, final Integer ne) {
		super(cla, ins, param1, param2, data, ne);
	}

}
