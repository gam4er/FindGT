using System;
using System.ServiceProcess;
using FindGT.Service.Runtime;

namespace FindGT.Service
{
    public sealed class FindGtWindowsService : ServiceBase
    {
        public const string InternalServiceName = "FindGT";
        private readonly string _configurationPath;
        private FindGtServiceRuntime _runtime;

        public FindGtWindowsService(string configurationPath)
        {
            _configurationPath = configurationPath;
            ServiceName = InternalServiceName;
            CanStop = true;
            CanShutdown = true;
            AutoLog = false;
        }

        protected override void OnStart(string[] args)
        {
            RequestAdditionalTime(30000);
            FindGtServiceRuntime runtime = ServiceRuntimeFactory.Create(
                _configurationPath,
                false);
            bool started = false;
            try
            {
                runtime.Start();
                _runtime = runtime;
                started = true;
            }
            finally
            {
                if (!started)
                {
                    runtime.Dispose();
                }
            }
        }

        protected override void OnStop()
        {
            StopRuntime();
        }

        protected override void OnShutdown()
        {
            StopRuntime();
            base.OnShutdown();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                StopRuntime();
            }

            base.Dispose(disposing);
        }

        private void StopRuntime()
        {
            FindGtServiceRuntime runtime = _runtime;
            _runtime = null;
            if (runtime == null)
            {
                return;
            }

            RequestAdditionalTime(30000);
            runtime.Stop(TimeSpan.FromSeconds(25));
            runtime.Dispose();
        }
    }
}
