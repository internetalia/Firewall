using System;
using System.Collections.Generic;
using System.Net;
using Microsoft.AspNetCore.Http;

namespace Firewall
{
    /// <summary>
    /// A Firewall rule which permits access to a list of specific IP addresses (proxy) when the client is also a valid address.
    /// </summary>
    public sealed class ReverseProxyClientIPAddressRangeRule : IFirewallRule
    {
        private readonly IFirewallRule _nextRule;
        private readonly IList<CIDRNotation> _cidrNotations;
        private readonly string _reverseProxyHeader;

        /// <summary>
        /// Initialises a new instance of <see cref="IPAddressRule"/>.
        /// </summary>
        public ReverseProxyClientIPAddressRangeRule(IFirewallRule nextRule, IList<CIDRNotation> cidrNotations, string reverseProxyHeader)
        {
            _nextRule = nextRule ?? throw new ArgumentNullException(nameof(nextRule));
            _cidrNotations = cidrNotations ?? throw new ArgumentNullException(nameof(cidrNotations));
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

                var (isAllowed, ip) = MatchesAnyIPAddressRange(remoteIpAddress);

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
                return false || _nextRule.IsAllowed(context);
            }
            
        }

        private (bool, CIDRNotation) MatchesAnyIPAddressRange(IPAddress remoteIpAddress)
        {
            if (_cidrNotations != null && _cidrNotations.Count > 0)
                foreach (var cidr in _cidrNotations)
                    if (cidr.Contains(remoteIpAddress))
                        return (true, cidr);

            return (false, null);
        }
    }
}