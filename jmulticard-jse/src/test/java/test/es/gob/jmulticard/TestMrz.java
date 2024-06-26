package test.es.gob.jmulticard;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.crypto.BcCryptoHelper;

/** Pruebas de an&aacute;lisis de MRZ.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestMrz {
                                    //  1                            30
	private static final String MRZ1 = "IDESPBKS116519811830960J<<<<<<" + //$NON-NLS-1$
	                                   "7501045M2909233ESP<<<<<<<<<<<9" + //$NON-NLS-1$
			                           "GARCIA<MERAS<CAPOTE<<TOMAS<<<<"; //$NON-NLS-1$

	                                //  1                                          44
	private static final String MRZ2 = "P<ESPGARCIA<MERAS<CAPOTE<<TOMAS<<<<<<<<<<<<<" + //$NON-NLS-1$
			                           "PAK1670410ESP7501045M2909233A1183096000<<<02"; //$NON-NLS-1$

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {
		//System.out.println(new Mrz(MRZ1));

		Mrz mrz = new Mrz(MRZ2);
		byte[] pwd = mrz.getMrzPswd(new BcCryptoHelper());
		System.out.println(HexUtils.hexify(pwd, false));
		System.out.println(HexUtils.hexify(new TestMrzInfo(MRZ1).getMrzPswd(new BcCryptoHelper()), false));

		mrz = new Mrz(MRZ2);
		pwd = mrz.getMrzPswd(new BcCryptoHelper());
		System.out.println(HexUtils.hexify(pwd, false));
		System.out.println(HexUtils.hexify(new TestMrzInfo(MRZ2).getMrzPswd(new BcCryptoHelper()), false));
	}
}
