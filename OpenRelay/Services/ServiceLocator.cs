using System;
using System.Collections.Generic;

namespace OpenRelay.Services
{
    /// <summary>
    /// Simple service locator to allow components to find services
    /// </summary>
    public static class ServiceLocator
    {
        private static readonly Dictionary<Type, object> _services = new Dictionary<Type, object>();

        /// <summary>
        /// Register a service
        /// </summary>
        public static void RegisterService<T>(T service) where T : class
        {
            _services[typeof(T)] = service;
        }

        /// <summary>
        /// Get a registered service
        /// </summary>
        public static T? GetService<T>() where T : class
        {
            if (_services.TryGetValue(typeof(T), out var service))
            {
                return (T)service;
            }
            return null;
        }

        /// <summary>
        /// Clear all registered services
        /// </summary>
        public static void Clear()
        {
            _services.Clear();
        }
    }
}