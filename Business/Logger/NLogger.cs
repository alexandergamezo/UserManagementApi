using Business.Interfaces;
using NLog;

namespace Business.Logger
{
    public class NLogger : INLogger
    {
        private static readonly NLog.Logger Logger = LogManager.GetLogger("fileLogger");

        public void LogInformation(string message)
        {
            Logger.Info(message);
        }

        public void LogWarning(string message)
        {
            Logger.Warn(message);
        }

        public void LogError(string message)
        {
            Logger.Error(message);
        }
    }
}
