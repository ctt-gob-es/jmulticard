package es.gob.jmulticard.apdu.iso7816four.pace;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationTemplateApduCommand;
import es.gob.jmulticard.asn1.icao.CardAccess;

/** APDU de establecimiento de algoritmo para PACE.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class MseSetPaceAlgorithmApduCommand extends MseSetAuthenticationTemplateApduCommand {

	/** Tipo de contrase&ntilde;a que se va a usar para establecer el canal PACE. */
	public enum PacePasswordType {

		/** MRZ (<i>Machine-Readable Zone</i>). */
		MRZ(
			new byte[] {
				/* T */ (byte) 0x83,
				/* L */ (byte) 0x01,
				/* V */ (byte) 0x01
			}
		),
		/** CAN (<i>Card Access Number</i>). */
		CAN(
			new byte[] {
				/* T */ (byte) 0x83,
				/* L */ (byte) 0x01,
				/* V */ (byte) 0x02
			}
		),
		/** PIN (<i>Personal Identification Number</i>). */
		PIN(
			new byte[] {
				/* T */ (byte) 0x83,
				/* L */ (byte) 0x01,
				/* V */ (byte) 0x03
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

	/** Crea una APDU de establecmiento de algoritmo para PACE.
	 * @param cla Clase (CLA) de la APDU.
	 * @param algorithm Algoritmo a utilizar.
	 * @param pwdType Tipo de contrase&ntilde;a que se va a usar para establecer el canal PACE.
	 * @param paceChat PACE CHAT de EACv2.
	 * @param algorithmParam Par&aacute;metro para el algoritmo de establecimiento de canal PACE. */
	public MseSetPaceAlgorithmApduCommand(final byte cla,
			                              final CardAccess.PaceAlgorithm algorithm,
			                              final PacePasswordType pwdType,
			                              final PaceChat paceChat,
			                              final CardAccess.PaceAlgorithmParam algorithmParam) {
		super(
			cla,
			HexUtils.concatenateByteArrays(
				new byte[] { (byte) 0x80 }, // Cryptographic mechanism reference
				algorithm.getBytes(),
				pwdType.getBytes(),
				paceChat != null ? paceChat.getBytes() : new byte[0],
				algorithmParam != null ? algorithmParam.getBytes() : new byte[0]
			)
		);
	}
}
