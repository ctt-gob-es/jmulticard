package es.gob.jmulticard.card.dnie;

import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.card.Atr;

/** ATR de un DNIe.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public final class DnieAtr extends Atr {

	private static final long serialVersionUID = -4364467785373401604L;

	/** Construye el ATR de un DNIe.
	 * @param cardAtr ATR de origen. */
	public DnieAtr(final Atr cardAtr) {
		super(cardAtr.getBytes(), cardAtr.getMask());
	}

	@Override
	public String toString() {

		if (atrBytes.length != 20 || atrBytes[0] != (byte) 0x3B) {
			return "ATR de la tarjeta: " + super.toString(); //$NON-NLS-1$
		}

		final StringBuilder sb = new StringBuilder("ATR del DNIe: "); //$NON-NLS-1$
		sb.append(super.toString());
		sb.append('\n');

		sb.append("  Vpp (voltaje de programacion): "); //$NON-NLS-1$
		sb.append(HexUtils.getShort(new byte[] { atrBytes[3] }, 0));
		if (atrBytes[3] == (byte) 0x00) {
			sb.append(" (no requerido)"); //$NON-NLS-1$
		}
		sb.append('\n');

		sb.append("  Tiempo de espera adicional: "); //$NON-NLS-1$
		sb.append(HexUtils.getShort(new byte[] { atrBytes[4] }, 0));
		if (atrBytes[4] == (byte) 0x00) {
			sb.append(" (no requerido)"); //$NON-NLS-1$
		}
		sb.append('\n');

		sb.append("  Nombre de la tarjeta: "); //$NON-NLS-1$
		sb.append(new String(new byte[] { atrBytes[7], atrBytes[8] , atrBytes[9], atrBytes[10] }));
		sb.append('\n');

		sb.append("  Fabricante de la tecnologia 'Match-on-Card' incorporada: "); //$NON-NLS-1$
		if (atrBytes[11] == (byte) 0x10) {
			sb.append("SAGEM"); //$NON-NLS-1$
		}
		else if (atrBytes[11] == (byte) 0x20) {
			sb.append("SIEMENS"); //$NON-NLS-1$
		}
		else {
			sb.append("desconocido"); //$NON-NLS-1$
		}
		sb.append('\n');

		sb.append("  Fabricante del chip: "); //$NON-NLS-1$
		if (atrBytes[12] == (byte) 0x02) {
			sb.append("STMicroelectronics"); //$NON-NLS-1$
		}
		else {
			sb.append("desconocido"); //$NON-NLS-1$
		}
		sb.append('\n');

		sb.append("  Tipo de chip: "); //$NON-NLS-1$
		if (atrBytes[13] == (byte) 0x4C && atrBytes[14] == (byte) 0x34) {
			sb.append("19WL34"); //$NON-NLS-1$
		}
		else {
			sb.append("desconocido"); //$NON-NLS-1$
		}
		sb.append('\n');

		sb.append("  Fase del ciclo de vida: "); //$NON-NLS-1$
		switch(atrBytes[17]) {
			case (byte) 0x00:
				sb.append("prepersonalizacion"); //$NON-NLS-1$
				break;
			case (byte) 0x01:
				sb.append("personalizacion"); //$NON-NLS-1$
				break;
			case (byte) 0x03:
				sb.append("usuario"); //$NON-NLS-1$
				break;
			case (byte) 0x0f:
				sb.append("final"); //$NON-NLS-1$
				break;
			default:
				sb.append("desconocido"); //$NON-NLS-1$
		}
		sb.append('\n');

		sb.append("  Estado: "); //$NON-NLS-1$
		if (atrBytes[18] == (byte) 0x90 && atrBytes[19] == 0x00) {
			sb.append("correcto"); //$NON-NLS-1$
		}
		else if (atrBytes[18] == (byte) 0x65 && atrBytes[19] == 0x81) {
			sb.append("memoria volatil borrada"); //$NON-NLS-1$
		}
		else {
			sb.append("desconocido"); //$NON-NLS-1$
		}

		return sb.toString();
	}
}
