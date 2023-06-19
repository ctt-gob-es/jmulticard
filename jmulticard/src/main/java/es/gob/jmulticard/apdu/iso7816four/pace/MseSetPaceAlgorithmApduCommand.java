package es.gob.jmulticard.apdu.iso7816four.pace;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationTemplateApduCommand;

/** APDU de establecmiiento de algoritmo para PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class MseSetPaceAlgorithmApduCommand extends MseSetAuthenticationTemplateApduCommand {

	/** Par&aacute;metro para el algoritmo de establecimiento de canal PACE. */
	public enum PaceAlgorithmParam {

		/** Curva <i>brainpool256r1</i>. */
		BRAINPOOL_256_R1(
			new byte[] {
				/* T */ (byte) 0x84,
				/* L */ (byte) 0x01,
				/* V */ (byte) 0x0d
			}
		);

		private final byte[] paramBytes;

		PaceAlgorithmParam(final byte[] paramId) {
			paramBytes = paramId.clone();
		}

		/** Obtiene la representaci&oacute;n binaria del OID.
		 * @return Representaci&oacute;n binaria del OID. */
		public byte[] getBytes() {
			return paramBytes.clone();
		}
	}

	/** Tipo de contrase&ntilde;a que se va a usar para establecer el canal PACE. */
	public enum PacePasswordType {

		/** MRZ <i>Machine-Readable Zone</i>. */
		MRZ(
			new byte[] {
				/* T */ (byte) 0x83,
				/* L */ (byte) 0x01,
				/* V */ (byte) 0x01
			}
		),
		/** CAN <i>Card Access Number</i>. */
		CAN(
			new byte[] {
				/* T */ (byte) 0x83,
				/* L */ (byte) 0x01,
				/* V */ (byte) 0x02
			}
		);

		private final byte[] pwdTypeBytes;

		PacePasswordType(final byte[] tpy) {
			pwdTypeBytes = tpy.clone();
		}

		/** Obtiene la representaci&oacute;n binaria del OID.
		 * @return Representaci&oacute;n binaria del OID. */
		public byte[] getBytes() {
			return pwdTypeBytes.clone();
		}
	}

	/** Algoritmo de establecimiento de canal PACE.
	 * <p>Los OID son una combinaci&oacute;n de:</p>
	 * <ul>
	 *   <li>0.4.0.127.0.7 (bsi-de)</li>
	 *   <li>
	 *     <ul>
	 *       <li>2.2.4 (id_PACE)</li>
	 *       <li>
	 *         <ul>
	 *           <li>1 (id_PACE_DH_GM)</li>
	 *           <li>2 (id_PACE_ECDH_GM)</li>
	 *           <li>3 (id_PACE_DH_IM)</li>
	 *           <lI>4 (id_PACE_ECDH_IM)</li>
	 *         </ul>
	 *       </li>
	 *     </ul>
	 *   </li>
	 * </ul> */
	public enum PaceAlgorithmOid {

		/** id_PACE_ECDH_GM_AES_CBC_CMAC_128 (OID 0.4.0.127.0.7.2.2.4.2.2). */
		PACE_ECDH_GM_AES_CBC_CMAC_128(
			new byte[] {
				/* T */
				/* L */ (byte) 0x0A,
				/* V */ (byte) 0x04, (byte) 0x00, (byte) 0x7f, (byte) 0x00, (byte) 0x07,
				        (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x02, (byte) 0x02
			}
		),

		/** id_PACE_DH_GM_AES_CBC_CMAC_128 (OID 0.4.0.127.0.7.2.2.4.1.2). */
		PACE_DH_GM_AES_CBC_CMAC_128(
			new byte[] {
				/* T */
				/* L */ (byte) 0x0A,
				/* V */ (byte) 0x04, (byte) 0x00, (byte) 0x7f, (byte) 0x00, (byte) 0x07,
				        (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x01, (byte) 0x02
			}
		);

		private final byte[] oidBytes;

		PaceAlgorithmOid(final byte[] oid) {
			oidBytes = oid.clone();
		}

		/** Obtiene la representaci&oacute;n binaria del OID.
		 * @return Representaci&oacute;n binaria del OID. */
		public byte[] getBytes() {
			return oidBytes.clone();
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
				new byte[]{(byte)0x80},
				algorithm.getBytes(),
				pwdType.getBytes(),
				algorithmParam.getBytes()
			)
		);
	}
}
