using System;
using System.Collections.Generic;
using System.Net;
using Microsoft.AspNetCore.Http;

namespace Firewall
{
    /// <summary>
    /// A Firewall rule which permits access to a list of specific IP addresses when accessing a particular hostname.
    /// </summary>
    public sealed class HostnameSpecificIPAddressRule : IFirewallRule
    {
        private readonly IFirewallRule _nextRule;
        private readonly IList<IPAddress> _ipAddresses;
        private readonly string _hostNamePartial;

        /// <summary>
        /// Initialises a new instance of <see cref="HostnameSpecificIPAddressRule"/>.
        /// </summary>
        public HostnameSpecificIPAddressRule(IFirewallRule nextRule, IList<IPAddress> ipAddresses, string hostnamePartial)
        {
            _nextRule = nextRule ?? throw new ArgumentNullException(nameof(nextRule));
            _ipAddresses = ipAddresses ?? throw new ArgumentNullException(nameof(ipAddresses));
            _hostNamePartial = hostnamePartial;
        }

        /// <summary>
        /// Denotes whether a given <see cref="HttpContext"/> is permitted to access the web server based on the client ip and requested host name.
        /// </summary>
        public bool IsAllowed(HttpContext context)
        {
            var remoteIpAddress = context.Connection.RemoteIpAddress;
            var (isAllowed, ip) = MatchesAnyIPAddress(remoteIpAddress);

            context.LogDebug(
                typeof(IPAddressRule),
                isAllowed,
                isAllowed
                    ? "it matched '{ipAddress}'"
                    : "it didn't match any known IP address",
                ip);
            //ip is valid and the hostname is matching, or check next rule
            return (isAllowed && context.Request.Host.ToString().ToLower().Contains(_hostNamePartial.ToLower())) || _nextRule.IsAllowed(context);
        }

        private (bool, IPAddress) MatchesAnyIPAddress(IPAddress remoteIpAddress)
        {
            if (_ipAddresses != null && _ipAddresses.Count > 0)
                foreach (var ip in _ipAddresses)
                    if (ip.IsEqualTo(remoteIpAddress))
                        return (true, ip);

            return (false, null);
        }
    }
}