package es.gob.jmulticard.apdu.iso7816four.pace;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationTemplateApduCommand;

/** APDU de establecmiiento de algoritmo para PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class MseSetPaceAlgorithmApduCommand extends MseSetAuthenticationTemplateApduCommand {

	/** Par&aacute;metro para el algoritmo de establecimiento de canal PACE. */
	public enum PaceAlgorithmParam {

		/** CAN <i>Card Access Number</i>. */
		BRAINPOOL_256_R1(
			new byte[] {
				/* T */ (byte) 0x84,
				/* L */ (byte) 0x01,
				/* V */ (byte) 0x0d
			}
		);

		private final byte[] paramBytes;

		private PaceAlgorithmParam(final byte[] paramId) {
			this.paramBytes = paramId.clone();
		}

		/** Obtiene la representaci&oacute;n binaria del OID.
		 * @return Representaci&oacute;n binaria del OID. */
		public byte[] getBytes() {
			return this.paramBytes.clone();
		}
	}

	/** Tipo de contrase&ntilde;a que se va a usar para establecer el canal PACE. */
	public enum PacePasswordType {

		/** CAN <i>Card Access Number</i>. */
		CAN(
			new byte[] {
				/* T */ (byte) 0x83,
				/* L */ (byte) 0x01,
				/* V */ (byte) 0x02
			}
		);

		private final byte[] pwdTypeBytes;

		private PacePasswordType(final byte[] tpy) {
			this.pwdTypeBytes = tpy.clone();
		}

		/** Obtiene la representaci&oacute;n binaria del OID.
		 * @return Representaci&oacute;n binaria del OID. */
		public byte[] getBytes() {
			return this.pwdTypeBytes.clone();
		}
	}

	/** Algoritmo de establecimiento de canal PACE. */
	public enum PaceAlgorithmOid {

		/** PACE-ECDH-GM-AES-CBC-CMAC-128. */
		PACE_ECDH_GM_AES_CBC_CMAC128(
			new byte[] {
				/* T */ (byte) 0x80,
				/* L */ (byte) 0x0A,
				/* V */ (byte) 0x04, (byte) 0x00, (byte) 0x7f, (byte) 0x00, (byte) 0x07,
				        (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x02, (byte) 0x02
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

	/** Crea una APDU de establecmiento de algoritmo para PACE.
	 * @param cla Clase (CLA) de la APDU.
	 * @param algorithm Algoritmo a utilizar.
	 * @param pwdType Tipo de contrase&ntilde;a que se va a usar para establecer el canal PACE.
	 * @param algorithmParam Par&aacute;metro para el algoritmo de establecimiento de canal PACE. */
	public MseSetPaceAlgorithmApduCommand(final byte cla,
			                              final PaceAlgorithmOid algorithm,
			                              final PacePasswordType pwdType,
			                              final PaceAlgorithmParam algorithmParam) {
		super(
			cla,
			HexUtils.concatenateByteArrays(
				algorithm.getBytes(),
				pwdType.getBytes(),
				algorithmParam.getBytes()
			)
		);
	}

}
