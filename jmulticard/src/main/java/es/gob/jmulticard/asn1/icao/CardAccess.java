package es.gob.jmulticard.asn1.icao;

import es.gob.jmulticard.DigestAlgorithm;

/** EF&#46;CardAccess de aplicaci&oacute;n de LDS1 para el eMRTD de ICAO 9303.
 * Implementaci&oacute;n ficticia hasta tener el correcto an&aacute;lisis de las estructuras ASN&#46;1.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class CardAccess {

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
	public enum PaceAlgorithm {

		/** id_PACE_ECDH_GM_AES_CBC_CMAC_128 (OID 0.4.0.127.0.7.2.2.4.2.2). */
		PACE_ECDH_GM_AES_CBC_CMAC_128(
			new byte[] {
				/* T */
				/* L */ (byte) 0x0A,
				/* V */ (byte) 0x04, (byte) 0x00, (byte) 0x7f, (byte) 0x00, (byte) 0x07,
				        (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x02, (byte) 0x02
			},
			128
		),

		/** id_PACE_ECDH_GM_AES_CBC_CMAC_192 (OID 0.4.0.127.0.7.2.2.4.2.3). */
		PACE_ECDH_GM_AES_CBC_CMAC_192(
			new byte[] {
				/* T */
				/* L */ (byte) 0x0A,
				/* V */ (byte) 0x04, (byte) 0x00, (byte) 0x7f, (byte) 0x00, (byte) 0x07,
				        (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x02, (byte) 0x03
			},
			192
		),

		/** id_PACE_DH_GM_AES_CBC_CMAC_128 (OID 0.4.0.127.0.7.2.2.4.1.2). */
		PACE_DH_GM_AES_CBC_CMAC_128(
			new byte[] {
				/* T */
				/* L */ (byte) 0x0A,
				/* V */ (byte) 0x04, (byte) 0x00, (byte) 0x7f, (byte) 0x00, (byte) 0x07,
				        (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x01, (byte) 0x02
			},
			128
		);

		private final byte[] oidBytes;
		private final int keyLength;

		PaceAlgorithm(final byte[] oid, final int keyLen) {
			oidBytes = oid.clone();
			keyLength = keyLen;
		}

		/** Obtiene la representaci&oacute;n binaria del OID.
		 * @return Representaci&oacute;n binaria del OID. */
		public byte[] getBytes() {
			return oidBytes.clone();
		}

		/** Obtiene la longitud de clave del algoritmo (en bits).
		 * @return Longitud (en bits) de clave del algoritmo. */
		public int getKeyLength() {
			return keyLength;
		}
	}

	/** Par&aacute;metro para el algoritmo de establecimiento de canal PACE. */
	public enum PaceAlgorithmParam {

		/** Curva <i>brainpool256r1</i>. */
		BRAINPOOL_256_R1(
			new byte[] {
				/* T */ (byte) 0x84,
				/* L */ (byte) 0x01,
				/* V */ (byte) 0x0d
			},
			"brainpoolp256r1" //$NON-NLS-1$
		);

		private final byte[] paramBytes;
		private final String curveName;

		PaceAlgorithmParam(final byte[] paramId, final String curve) {
			paramBytes = paramId.clone();
			curveName = curve;
		}

		/** Obtiene la representaci&oacute;n binaria del OID.
		 * @return Representaci&oacute;n binaria del OID. */
		public byte[] getBytes() {
			return paramBytes.clone();
		}

		/** Obtiene el nombre de la curva (el&iacute;ptica).
		 * @return Nombre de la curva (el&iacute;ptica), o <code>null</code>
		 *         si el algoritmo no es de curva el&iacute;ptica. */
		public String getCurveName() {
			return curveName;
		}
	}

	private final PaceAlgorithm paceAlgorithm;
	private final PaceAlgorithmParam paceAlgorithmParam;
	private final DigestAlgorithm paceDigestAlgorithm;

	/** Construye un CardAccess de ICAO 9303.
     * Es una implementaci&oacute;n ficticia que recibe los datos en el constructor.
	 * @param algorithm Algoritmo de establecimiento del canal PACE.
	 * @param algorithmParam Par&aacute;metros del algoritmo de establecimiento del canal PACE.
	 * @param digestAlgorithm Algoritmo de huella a usar en el establecimiento de canal PACE. */
	public CardAccess(final PaceAlgorithm algorithm,
			          final PaceAlgorithmParam algorithmParam,
			          final DigestAlgorithm digestAlgorithm) {
		paceAlgorithm = algorithm;
		paceAlgorithmParam = algorithmParam;
		paceDigestAlgorithm = digestAlgorithm;
	}

	/** Obtiene el algoritmo de establecimiento de canal PACE.
	 * @return Algoritmo de establecimiento de canal PACE. */
	public PaceAlgorithm getPaceAlgorithm() {
		return paceAlgorithm;
	}

	/** Obtiene el par&aacute;metro del algoritmo de establecimiento de canal PACE.
	 * @return Par&aacute;metro del algoritmo de establecimiento de canal PACE. */
	public PaceAlgorithmParam getPaceAlgorithmParam() {
		return paceAlgorithmParam;
	}

	/** Obtiene el algoritmo de huella a usar en el establecimiento de canal PACE.
	 * @return Algoritmo de huella a usar en el establecimiento de canal PACE. */
	public DigestAlgorithm getPaceDigestAlgorithm() {
		return paceDigestAlgorithm;
	}
}
