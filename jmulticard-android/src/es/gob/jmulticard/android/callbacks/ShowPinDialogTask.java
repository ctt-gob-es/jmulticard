package es.gob.jmulticard.android.callbacks;

import android.app.Activity;
import android.os.AsyncTask;
import android.support.v4.app.FragmentTransaction;

/**
 * Created by a621914 on 08/06/2016.
 */

class ShowPinDialogTask extends AsyncTask<String, String, String> {

    final PinDialog dialog;
	private final FragmentTransaction ft;
	private static Activity activity;
	static DialogDoneChecker dialogDone;

	private OnTaskCompleted listener;

	ShowPinDialogTask(final PinDialog dialog, final FragmentTransaction ft, final Activity act, final DialogDoneChecker ddc) {
    	this.dialog = dialog;
    	this.ft = ft;
    	activity = act;
    	dialogDone = ddc;
    }

	public String getPassword() {
		return this.m_Input;
	}
	@Override
	protected synchronized String doInBackground(final String... arg0) {
        return this.m_Input;
	};

	String m_Input;

	public synchronized String getInput()
	{

		activity.runOnUiThread(new Runnable()
	    {
	        @Override
	        public void run()
	        {
	        	ShowPinDialogTask.this.dialog.show(ShowPinDialogTask.this.ft, "PIN");
	        }
	    });

		try
	    {
	    	synchronized(dialogDone) {
	    		dialogDone.wait();
            	}
	    }
	    catch (final InterruptedException e)
	    {
	    }

		this.m_Input = this.dialog.getPassword();
	    return this.m_Input;
	}
}

