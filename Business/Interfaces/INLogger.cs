﻿namespace Business.Interfaces
{
    public interface INLogger
    {
        void LogInformation(string message);
        void LogWarning(string message);
        void LogError(string message);
    }

}
