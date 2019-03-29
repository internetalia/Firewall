using System;
using System.Collections.Generic;
using System.Net;
using Microsoft.AspNetCore.Http;

namespace Firewall
{
    /// <summary>
    /// A Firewall rule which permits access to a list of specific IP addresses (proxy) when the client is also a valid address.
    /// </summary>
    public sealed class ReverseProxyClientIPAddressRule : IFirewallRule
    {
        private readonly IFirewallRule _nextRule;
        private readonly IList<IPAddress> _ipAddresses;
        private readonly string _reverseProxyHeader;

        /// <summary>
        /// Initialises a new instance of <see cref="IPAddressRule"/>.
        /// </summary>
        public ReverseProxyClientIPAddressRule(IFirewallRule nextRule, IList<IPAddress> ipAddresses, string reverseProxyHeader)
        {
            _nextRule = nextRule ?? throw new ArgumentNullException(nameof(nextRule));
            _ipAddresses = ipAddresses ?? throw new ArgumentNullException(nameof(ipAddresses));
            _reverseProxyHeader = reverseProxyHeader;
        }

        /// <summary>
        /// Denotes whether a given <see cref="HttpContext"/> is permitted to access the web server.
        /// </summary>
        public bool IsAllowed(HttpContext context)
        {

            IPAddress remoteIpAddress;
            if (IPAddress.TryParse(context.Request.Headers[_reverseProxyHeader], out remoteIpAddress))
            {

                var (isAllowed, ip) = MatchesAnyIPAddress(remoteIpAddress);

                context.LogDebug(
                    typeof(ReverseProxyClientIPAddressRule),
                    isAllowed,
                    isAllowed
                        ? "it matched '{ipAddress}'"
                        : "it didn't match any known IP address",
                    ip);
                //by default the reverse proxy rule will match the client ip is valid AND check the reverse proxy ip is valid
                return isAllowed && _nextRule.IsAllowed(context);
            }
            else {
                context.Log(Microsoft.Extensions.Logging.LogLevel.Error,
                    typeof(ReverseProxyClientIPAddressRule),
                       "Invalid reverse proxy header '{_reverseProxyHeader}' or unable to parse remote ip ",
                    _reverseProxyHeader);
                return false;
            }
            
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