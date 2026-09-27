package app.payguard.shield;

import android.app.job.JobParameters;
import android.app.job.JobService;

/** Runs Family.poll() in the background about every 15 minutes so guardians see alerts without opening the app. */
public class AlertJobService extends JobService {
    private volatile Thread worker;

    @Override
    public boolean onStartJob(final JobParameters params) {
        worker = new Thread(() -> {
            Family.poll(getApplicationContext());
            jobFinished(params, false);
        });
        worker.start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        Thread t = worker;
        if (t != null) t.interrupt();
        return true; // try again later
    }
}
