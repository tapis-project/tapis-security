package edu.utexas.tacc.tapis.jobs.monitors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.utexas.tacc.tapis.jobs.exceptions.JobException;
import edu.utexas.tacc.tapis.jobs.model.Job;
import edu.utexas.tacc.tapis.jobs.model.enumerations.JobRemoteOutcome;
import edu.utexas.tacc.tapis.jobs.model.enumerations.JobStatusType;
import edu.utexas.tacc.tapis.jobs.monitors.parsers.JobRemoteStatus;
import edu.utexas.tacc.tapis.jobs.monitors.policies.MonitorPolicy;
import edu.utexas.tacc.tapis.jobs.worker.execjob.JobExecutionContext;
import edu.utexas.tacc.tapis.shared.exceptions.TapisException;
import edu.utexas.tacc.tapis.shared.exceptions.recoverable.TapisRecoverableException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;

abstract class AbstractJobMonitor
 implements JobMonitor
{
    /* ********************************************************************** */
    /*                               Constants                                */
    /* ********************************************************************** */
    // Tracing.
    private static final Logger _log = LoggerFactory.getLogger(AbstractJobMonitor.class);

    /* ********************************************************************** */
    /*                                 Fields                                 */
    /* ********************************************************************** */
    protected final MonitorPolicy       _policy;
    protected final JobExecutionContext _jobCtx;
    protected final Job                 _job;

    /* ********************************************************************** */
    /*                              Constructors                              */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    protected AbstractJobMonitor(JobExecutionContext jobCtx, MonitorPolicy policy)
    {
        _policy = policy;
        _jobCtx = jobCtx;
        _job    = jobCtx.getJob();
    }

    /* ********************************************************************** */
    /*                             Public Methods                             */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* monitorQueuedJob:                                                      */
    /* ---------------------------------------------------------------------- */
    @Override
    public void monitorQueuedJob() throws TapisException
    {
        monitor(JobStatusType.QUEUED);
    }

    /* ---------------------------------------------------------------------- */
    /* monitorRunningJob:                                                     */
    /* ---------------------------------------------------------------------- */
    @Override
    public void monitorRunningJob() throws TapisException
    {
        monitor(JobStatusType.RUNNING);
    }

    /* ---------------------------------------------------------------------- */
    /* closeConnection:                                                       */
    /* ---------------------------------------------------------------------- */
    @Override
    public void closeConnection() 
    {
        // Is there anything to do?
        if (!_jobCtx.existsExecSystemConnection()) return;
        try {
            // Only delete sessions with at most a single channel,
            // the channel used for monitoring.
            var conn = _jobCtx.getExecSystemConnection();
            if (conn.getChannelCount() <= 1) _jobCtx.closeExecSystemConnection();
        } catch (Exception e) {
            // Just log the problem.
            _log.error(e.getMessage(), e);
        }
    }
    
    /* ********************************************************************** */
    /*                          Protected Methods                             */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* allowEmptyResult:                                                      */
    /* ---------------------------------------------------------------------- */
    /** This method determines whether the result of a monitoring 
     * request can be empty or not.  When true is returned, empty
     * results from a monitor query do not cause an exception to
     * be thrown.  When false is returned, the remote client code
     * considers an empty response to be an error and throws an
     * exception.
     * 
     * @return true to allow empty monitoring results, false otherwise
     */
    protected boolean allowEmptyResult() {return false;}
    
    /* ---------------------------------------------------------------------- */
    /* queryRemoteJob:                                                        */
    /* ---------------------------------------------------------------------- */
    /** Return a non-null remote job status value.  Subclasses must issue the
     * query on the ssh connection to execution system.  The active flag allows
     * the query to be tailored to the state of the remote job.  Specify 
     * active=true for any state before the job terminates; specify active=false
     * after the job has terminated.
     * 
     * 
     * @param active true for pre-termination, false for post-termination
     * @return non-null remote job status
     */
    protected abstract JobRemoteStatus queryRemoteJob(boolean active) throws TapisException;
    
    /* ---------------------------------------------------------------------- */
    /* monitor:                                                               */
    /* ---------------------------------------------------------------------- */
    /** This is the actual monitor call.  The initial status values determine
     * how a remote status change is detected.  The only two valid initial status 
     * values are QUEUE and RUNNING.  Subclasses implement the abstract methods
     * of this class to issue the actual query commands on the execution system.
     * Subclasses can also override the JobMonitor interface's methods to take
     * control of monitoring before it reaches this method.
     * 
     * The general approach is to issue monitoring queries until the remote job's 
     * status changes.  The frequency and other limits placed on querying are
     * the determined by the policy settings.  When a change is detected monitoring 
     * ceases and control is returned to the caller.  When a limit is exceeded an
     * exception is thrown indicating to the caller that the job should be 
     * considered FAILED.
     * 
     * Depending on the policy settings, long intervals between monitor queries
     * may cause the connection to the execution system to be closed.
     * 
     * Under normal conditions, when a job terminates the remote job outcome
     * and exit code are retrieved and used to update the job in memory and 
     * in the database.  
     */
    protected void monitor(final JobStatusType initialStatus)
     throws TapisException
    {
        // Sanity check.
        if (initialStatus != JobStatusType.QUEUED && initialStatus != JobStatusType.RUNNING)
        {    
            String msg = MsgUtils.getMsg("TAPIS_INVALID_PARAMETER", "monitor", "initialStatus", initialStatus);
            throw new JobException(msg);
        }
        
        // We put all code inside the try block so that we can guarantee the job 
        // outcome will always be set during this phase.
        boolean recoverableExceptionThrown = false;
        try {
            // Monitor the remote job as prescribed by the monitor policy until
            // it reaches a terminal state or a policy limit has been reached.
            boolean lastAttemptFailed = false; // no failed monitoring attempts yet!
            while (true) 
            {
                // ------------------------- Consult Policy --------------------------
                Long waitMillis = _policy.millisToWait(lastAttemptFailed);
                if (waitMillis == null) {
                    // Set the job outcome so that archiving is skipped since the job may
                    // still be running or start running at some point in the future.
                    _jobCtx.getJobsDao().setRemoteOutcome(_job, JobRemoteOutcome.FAILED_SKIP_ARCHIVE);
                
                    // We want to update the finalMessage field in the jobCtx, which will be used to update the lastMessage field in the db. 
                    String finalMessage = MsgUtils.getMsg("JOBS_EARLY_TERMINATION", _policy.getReasonCode().name());
                    _jobCtx.setFinalMessage(finalMessage);
                
                    // Signal that this job is kaput.
                    String msg = MsgUtils.getMsg("JOBS_MONITOR_EARLY_TERMINATION", getClass().getSimpleName(),
                                                 _job.getUuid(), _policy.getReasonCode().name(),
                                                 _job.getRemoteOutcome().name());
                    throw new JobException(msg);
                }
                
                // *** Async command check ***
                _jobCtx.checkCmdMsg();
            
                // Wait the policy-determined number of milliseconds; exceptions are logged.
                try {Thread.sleep(waitMillis);} 
                    catch (InterruptedException e) {
                        if (_log.isDebugEnabled()) {
                            String msg = MsgUtils.getMsg("JOBS_MONITOR_INTERRUPTED", _job.getUuid(), 
                                                         getClass().getSimpleName());
                            _log.debug(msg);
                        }
                    }
            
                // *** Async command check ***
                _jobCtx.checkCmdMsg();
            
                // ------------------------- Request Status --------------------------
                // The query method never returns null.  It's first called assuming the job is active
                // and, if necessary, called assuming the job has terminated.  The implementing
                // subclass chooses how to support each of the calls.
                JobRemoteStatus remoteStatus = queryRemoteJob(true);
                if (remoteStatus == JobRemoteStatus.NULL || remoteStatus == JobRemoteStatus.EMPTY)
                    remoteStatus = queryRemoteJob(false);
                
                // We keep the connection open if we might use it again soon.
                if (!_policy.keepConnection()) closeConnection();
                
                // --------------------- Process Failed Attempts ---------------------
                // Detect a possible initial queuing race condition and
                // let the policy determine whether we should retry.
                if (remoteStatus == JobRemoteStatus.EMPTY || remoteStatus == JobRemoteStatus.NULL) 
                    if (_policy.retryForInitialQueuing()) continue;
                
                // If the status problem hasn't cleared up by now, we assume that the problem
                // retrieving the status is not due to an initial race condition but some
                // other issue.  This code saves the attempt information in the database.
                if (remoteStatus == JobRemoteStatus.EMPTY || remoteStatus == JobRemoteStatus.NULL) 
                {
                    // Let's record this failure attempt.
                    lastAttemptFailed = true;
                    
                    // Update the job monitoring counter and its persistent 
                    // record in the database. An exception can be thrown here.
                    final boolean success = false;
                    _jobCtx.getJobsDao().incrementRemoteStatusCheck(_job, success);
                    
                    // Try again.
                    continue;
                }
                
                // The monitoring command did not fail, so we can update the job monitoring counter
                // and its persistent record in the database now. An exception can be thrown here.
                final boolean success = true;
                _jobCtx.getJobsDao().incrementRemoteStatusCheck(_job, success);
                
                // --------------------- Process No-Change ---------------------------
                // Is the remote job's status still compatible with our initial status? 
                boolean noChange;
                if (initialStatus == JobStatusType.QUEUED) noChange = remoteStatus == JobRemoteStatus.QUEUED;
                  else noChange = remoteStatus == JobRemoteStatus.ACTIVE;
                if (noChange) {
                    // Clear any failure history and continue normally.
                    lastAttemptFailed = false;
                    continue;
                }
                
                // --------------------- Process Advancement -------------------------
                // Has the remote job moved off the queue and into an active execution state?
                if (initialStatus == JobStatusType.QUEUED && remoteStatus == JobRemoteStatus.ACTIVE) 
                    break;
                
                // --------------------- Process Termination -------------------------
                // Are we in a terminal state?
                if (remoteStatus == JobRemoteStatus.DONE || remoteStatus == JobRemoteStatus.FAILED) 
                {
                    // The exit code is always set.
                    var code = getExitCode();
                    
                    // Set the job outcome. Finished is our success code. If the job failed,
                    // then we skip archiving unless the user explicitly specified that 
                    // archiving should be performed even on failures.
                    if (remoteStatus == JobRemoteStatus.DONE) 
                        _jobCtx.getJobsDao().setRemoteOutcomeAndResult(_job, JobRemoteOutcome.FINISHED, code);
                    else if (_job.isArchiveOnAppError())
                        _jobCtx.getJobsDao().setRemoteOutcomeAndResult(_job, JobRemoteOutcome.FAILED, code);
                    else _jobCtx.getJobsDao().setRemoteOutcomeAndResult(_job, JobRemoteOutcome.FAILED_SKIP_ARCHIVE, code);
                    
                    // Record the outcome.  
                    if (_log.isDebugEnabled()) {
                        String msg = MsgUtils.getMsg("JOBS_MONITOR_FINISHED", getClass().getSimpleName(),
                                                     _job.getUuid(), remoteStatus.name(),
                                                     _job.getRemoteOutcome().name(), code);
                        _log.debug(msg);
                    }
                    
                    // We're done monitoring.
                    break;
                }
            }
        }
        catch (Exception e) {
            // We need to do two things in this catch clause:
            //   
            //  1. Wrap unrecoverable exceptions that meet certain conditions in a recoverable  
            //     exception and throw that new outer exception.
            //  2. Set the recoverable flag if a recoverable exception is thrown from this 
            //     catch clause.
                
            // Are we dealing with a recoverable condition?  Connection problems are always
            // treated as recoverable, see the recovery code in TenantQueueProcessor.
            if (e instanceof TapisRecoverableException) 
            {
                // Do not set the outcome when monitoring will resume in the future.
                recoverableExceptionThrown = true;
            } 
        }
        finally {
            // Make sure the job outcome is set.  If we got here via an exception,
            // the outcome is not set.  We set it so that archiving is not performed
            // since the timing of the archiving cannot be coordinated with job 
            // execution if it is or will be executing.  
            if (!recoverableExceptionThrown && _job.getRemoteOutcome() == null) {
                // An exception could be thrown from here.
                _jobCtx.getJobsDao().setRemoteOutcome(_job, JobRemoteOutcome.FAILED_SKIP_ARCHIVE);
                
                // Record the outcome. The hardcoded remote status parameter is not significant.
                if (_log.isDebugEnabled()) {
                    String outcome = _job.getRemoteOutcome() == null ? "null" : _job.getRemoteOutcome().name();
                    String msg = MsgUtils.getMsg("JOBS_MONITOR_FINISHED", getClass().getSimpleName(),
                                                 _job.getUuid(), JobRemoteStatus.NULL.name(), outcome, null);
                    _log.debug(msg);
                }
            }
        }
    }
}
