package es.gob.jmulticard.asn1.icao;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.asn1.OptionalDecoderObjectElement;
import es.gob.jmulticard.asn1.Tlv;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.DerInteger;
import es.gob.jmulticard.asn1.der.OctectString;
import es.gob.jmulticard.asn1.der.Sequence;

/** Huella de Grupo de Datos (<code>DataGroupHash</code>) de ICAO MRTD.
 * <pre>
 *  DataGroupHash  ::=  SEQUENCE {
 *     dataGroupNumber     DataGroupNumber,
 *     dataGroupHashValue  OCTET STRING
 *  }
 *
 *  DataGroupNumber ::= INTEGER {
 *     dataGroup1    (1),
 *     dataGroup1    (2),
 *     dataGroup1    (3),
 *     dataGroup1    (4),
 *     dataGroup1    (5),
 *     dataGroup1    (6),
 *     dataGroup1    (7),
 *     dataGroup1    (8),
 *     dataGroup1    (9),
 *     dataGroup1    (10),
 *     dataGroup1    (11),
 *     dataGroup1    (12),
 *     dataGroup1    (13),
 *     dataGroup1    (14),
 *     dataGroup1    (15),
 *     dataGroup1    (16)
 *  }
 * </pre>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class DataGroupHash extends Sequence {

	/** Constructor. */
	public DataGroupHash() {
		super(
			new OptionalDecoderObjectElement[] {
				new OptionalDecoderObjectElement(
					DerInteger.class,
					false
				),
				new OptionalDecoderObjectElement(
					OctectString.class,
					false
				)
			}
		);
	}

	@Override
	public String toString() {
		String dataGroupHashValue;
		try {
			dataGroupHashValue = HexUtils.hexify(
				new Tlv(
					((OctectString)getElementAt(1)).getBytes()
				).getValue(),
				false
			);
		}
		catch (final TlvException e) {
			dataGroupHashValue = "INVALIDO (" + e + ")"; //$NON-NLS-1$ //$NON-NLS-2$
		}
		return "DataGroupHash para el DG" + getElementAt(0) + //$NON-NLS-1$
			" con valor de huella: " + dataGroupHashValue; //$NON-NLS-1$
	}

	/** Obtiene el ordinal del grupo de datos.
	 * @return Ordinal del grupo de datos. */
	public int getDataGroupNumber() {
		return ((DerInteger)getElementAt(0)).getIntegerValue().intValue();
	}

	/** Obtiene el valor de la huella del grupo de datos.
	 * @return Valor de la huella del grupo de datos.
	 * @throws TlvException Si no se puede obtener el valor de la huella a partir del TLV. */
	public byte[] getDataGroupHashValue() throws TlvException {
		return new Tlv(
			((OctectString)getElementAt(1)).getBytes()
		).getValue();
	}

}
