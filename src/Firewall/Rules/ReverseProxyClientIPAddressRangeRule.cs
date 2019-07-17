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
        private readonly IList<CIDRNotation> _validReverseProxyCIDRs;
        private readonly IList<IPAddress> validReverseProxyIps;
        private readonly List<CIDRNotation> allowedClientIPAddressRanges;
        private readonly string _reverseProxyHeader;

        /// <summary>
        /// Initialises a new instance of <see cref="IPAddressRule"/>.
        /// </summary>
        public ReverseProxyClientIPAddressRangeRule(IFirewallRule nextRule, IList<CIDRNotation> cidrNotations, IList<IPAddress> ips, List<CIDRNotation> allowedClientIPAddressRanges, string reverseProxyHeader)
        {
            _nextRule = nextRule ?? throw new ArgumentNullException(nameof(nextRule));
            _validReverseProxyCIDRs = cidrNotations ?? throw new ArgumentNullException(nameof(cidrNotations));
            this.validReverseProxyIps = ips;
            this.allowedClientIPAddressRanges = allowedClientIPAddressRanges;
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

                var (isClientIPAllowed, ip) = MatchesAnyIPAddressRange(remoteIpAddress, allowedClientIPAddressRanges);


                var (isReversProxyIPValid, _) = MatchesAnyIPAddress(context.Connection.RemoteIpAddress, validReverseProxyIps); // the ip addresses of the reverse proxy
                var (isReversProxyIPInCIDR, _) = MatchesAnyIPAddressRange(context.Connection.RemoteIpAddress, _validReverseProxyCIDRs); // the ip addresses of the reverse proxy


                context.LogDebug(
                    typeof(ReverseProxyClientIPAddressRangeRule),
                    isClientIPAllowed,
                    isClientIPAllowed
                        ? "it matched '{ipAddress}'"
                        : "it didn't match any known IP address",
                    ip);
                //by default the reverse proxy rule will match the client ip is valid AND check the reverse proxy ip is valid
                return (isClientIPAllowed && (isReversProxyIPValid || isReversProxyIPInCIDR)) || _nextRule.IsAllowed(context);
            }
            else {
                context.Log(Microsoft.Extensions.Logging.LogLevel.Error,
                    typeof(ReverseProxyClientIPAddressRangeRule),
                       "Invalid reverse proxy header '{_reverseProxyHeader}' or unable to parse remote ip ",
                    _reverseProxyHeader);
                return false;
            }
            
        }

        private (bool, IPAddress) MatchesAnyIPAddress(IPAddress remoteIpAddress, IList<IPAddress> allowList)
        {
            //if an ip address is supplied it must match for this rule to pass
            if (allowList != null && allowList.Count > 0)
                foreach (var ip in allowList)
                    if (ip.IsEqualTo(remoteIpAddress))
                        return (true, ip);

            return (false, null);

        }

        private (bool, CIDRNotation) MatchesAnyIPAddressRange(IPAddress remoteIpAddress, IList<CIDRNotation> reverseProxyCIDRs)
        {

            //if an ip address is supplied it must match for this rule to pass
            if (reverseProxyCIDRs != null && reverseProxyCIDRs.Count > 0)
                foreach (var cidr in reverseProxyCIDRs)
                    if (cidr.Contains(remoteIpAddress))
                        return (true, cidr);

            return (false, null);

        }
    }
}