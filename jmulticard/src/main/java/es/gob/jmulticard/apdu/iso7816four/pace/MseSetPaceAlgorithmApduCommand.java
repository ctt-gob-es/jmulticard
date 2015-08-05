package es.gob.jmulticard.apdu.iso7816four.pace;

import es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationTemplateApduCommand;

/** APDU de establecmiiento de algoritmo para PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class MseSetPaceAlgorithmApduCommand extends MseSetAuthenticationTemplateApduCommand {

	/** Algoritmo para PACE. */
	public enum PaceAlgorithmOid {

		/** PACE-ECDH-GM-AES-CBC-CMAC-128. */
		PACE_ECDH_GM_AES_CBC_CMAC_128(
			new byte[] {
				/* T */ (byte) 0x80,
				/* L */ (byte) 0x0A,
				/* V */ (byte) 0x04, (byte) 0x00, (byte) 0x7f, (byte) 0x00, (byte) 0x07,
				        (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x01, (byte) 0x02
			}
		);

		private final byte[] oidBytes;

		private PaceAlgorithmOid(final byte[] oid) {
			this.oidBytes = oid.clone();
		}

		/** Obtiene la representaci&oacute;n binaria del OID.
		 * @return Representaci&oacute;n binaria del OID. */
		public byte[] getBytes() {
			return this.oidBytes.clone();
		}
	}

	/** Crea una APDU de establecmiiento de algoritmo para PACE.
	 * @param cla Clase (CLA) de la APDU.
	 * @param algorithm Algoritmo a utilizar. */
	public MseSetPaceAlgorithmApduCommand(final byte cla, final PaceAlgorithmOid algorithm) {
		super(cla, algorithm.getBytes());
	}


}
