package es.gob.jmulticard.card.dnie;

/**
 * Interfaz para identificar los elementos que cachean informaci&oacute;n del usuario
 * y que nos permite reiniciarlos si es posible.
 */
public interface CacheElement {

	/**
	 * Reinicia los valores del elemento.
	 */
	void reset();
}
