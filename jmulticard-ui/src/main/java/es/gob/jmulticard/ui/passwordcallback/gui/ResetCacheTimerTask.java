package es.gob.jmulticard.ui.passwordcallback.gui;

import java.util.TimerTask;

import es.gob.jmulticard.card.dnie.CacheElement;

/** Tarea para el borrado de los datos <i>cacheados</i> por un elemento. */
final class ResetCacheTimerTask extends TimerTask {

	private final CacheElement element;

	ResetCacheTimerTask(final CacheElement element) {
		this.element = element;
	}

	@Override
	public void run() {
		if (this.element != null) {
			this.element.reset();
		}
	}
}
