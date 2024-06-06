package es.gob.jmulticard;

/** Algoritmo de huella digital.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public enum DigestAlgorithm {

	/** SHA-1. */
	SHA1("SHA1", 20), //$NON-NLS-1$

	/** SHA-256. */
	SHA256("SHA-256", 32), //$NON-NLS-1$

	/** SHA-384. */
	SHA384("SHA-384", 48), //$NON-NLS-1$

	/** SHA-512. */
	SHA512("SHA-512", 64); //$NON-NLS-1$

	/** Nombre del algoritmo de huella digital. */
	private final String name;

	/** Longitud (en octetos) de las huellas resultantes con este algoritmo.
	 * La longitud se proporciona est&aacute;ticamente para no introducir aqu&iacute;
	 * dependencias con proveedores de seguridad de Java o con BouncyCastle. */
	private final int length;

	/** Construye el algoritmo de huella digital.
	 * @param n Nombre del algoritmo.
	 * @param l Longitud (en octetos) de las huellas resultantes con este algoritmo. */
	DigestAlgorithm(final String n, final int l) {
		name = n;
		length = l;
	}

	@Override
	public String toString() {
		return name;
	}

	/** Obtiene la longitud (en octetos) de las huellas resultantes con este algoritmo.
	 * @return Longitud (en octetos) de las huellas resultantes con este algoritmo. */
	public int getDigestLength() {
		return length;
	}

	/** Obtiene un algoritmo de huella digital a partir de su nombre.
	 * @param name Nombre del algoritmo de huella digital a partir de su nombre.
	 * @return Algoritmo de huella digital. */
	public static DigestAlgorithm getDigestAlgorithm(final String name) {
		if ("SHA1".equals(name) || "SHA-1".equals(name)) { //$NON-NLS-1$ //$NON-NLS-2$
			return SHA1;
		}
		if ("SHA256".equals(name) || "SHA-256".equals(name)) { //$NON-NLS-1$ //$NON-NLS-2$
			return SHA256;
		}
		if ("SHA384".equals(name) || "SHA-384".equals(name)) { //$NON-NLS-1$ //$NON-NLS-2$
			return SHA384;
		}
		if ("SHA512".equals(name) || "SHA-512".equals(name)) { //$NON-NLS-1$ //$NON-NLS-2$
			return SHA512;
		}
		throw new IllegalArgumentException("Algoritmo de huella no soportado: " + name); //$NON-NLS-1$
	}
}
