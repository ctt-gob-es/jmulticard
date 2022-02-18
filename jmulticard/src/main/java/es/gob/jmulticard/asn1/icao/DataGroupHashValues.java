package es.gob.jmulticard.asn1.icao;

import es.gob.jmulticard.asn1.der.SequenceOf;

/** <code>DataGroupHashValues</code> de ICAO MRTD.
 * <pre>
 *   dataGroupHashValues ::= SEQUENCE OF DataHashGroup
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class DataGroupHashValues extends SequenceOf {

	/** Constructor. */
	public DataGroupHashValues() {
		super(DataGroupHash.class);
	}

	/** Obtiene los <code>DataGroupHash</code>.
	 * @return Array de <code>DataGroupHash</code>. */
	public DataGroupHash[] getDataGroupsHashes() {
		final DataGroupHash[] ret = new DataGroupHash[getElementCount()];
		for (int i=0; i<getElementCount(); i++) {
			ret[i] = (DataGroupHash) getElementAt(i);
		}
		return ret;
	}

}
