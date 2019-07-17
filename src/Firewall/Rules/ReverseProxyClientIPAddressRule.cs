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
        private readonly IList<IPAddress> _reverseProxyIPAddresses;
        private readonly List<IPAddress> _allowedClientIPAddresses;
        private readonly string _reverseProxyHeader;
        private readonly IList<CIDRNotation> _reverseProxyCIDRs;

        /// <summary>
        /// Initialises a new instance of <see cref="IPAddressRule"/>.
        /// </summary>
        public ReverseProxyClientIPAddressRule(IFirewallRule nextRule, IList<CIDRNotation> cidrs, IList<IPAddress> ipAddresses, List<IPAddress> allowedClientIPAddresses, string reverseProxyHeader)
        {
            _nextRule = nextRule ?? throw new ArgumentNullException(nameof(nextRule));
            _reverseProxyIPAddresses = ipAddresses ?? throw new ArgumentNullException(nameof(ipAddresses));
            this._allowedClientIPAddresses = allowedClientIPAddresses;
            _reverseProxyHeader = reverseProxyHeader;
            _reverseProxyCIDRs = cidrs;

        }

        /// <summary>
        /// Denotes whether a given <see cref="HttpContext"/> is permitted to access the web server.
        /// </summary>
        public bool IsAllowed(HttpContext context)
        {

            IPAddress remoteIpAddress;
            if (IPAddress.TryParse(context.Request.Headers[_reverseProxyHeader], out remoteIpAddress))
            {

                var (isClientIPAllowed, ip) = MatchesAnyIPAddress(remoteIpAddress,_allowedClientIPAddresses);


                var (isReversProxyIPValid, _) = MatchesAnyIPAddress(context.Connection.RemoteIpAddress, _reverseProxyIPAddresses); // the ip addresses of the reverse proxy
                var (isReversProxyIPInCIDR, _) = MatchesAnyIPAddressRange(context.Connection.RemoteIpAddress, _reverseProxyCIDRs); // the ip addresses of the reverse proxy

                context.LogDebug(
                    typeof(IPAddressRule),
                    isClientIPAllowed,
                    isClientIPAllowed
                        ? "it matched '{ipAddress}'"
                        : "it didn't match any known IP address",
                    ip);

                return (isClientIPAllowed && (isReversProxyIPValid || isReversProxyIPInCIDR)) || _nextRule.IsAllowed(context);


            }
            else {
                context.Log(Microsoft.Extensions.Logging.LogLevel.Error,
                    typeof(ReverseProxyClientIPAddressRule),
                       "Invalid reverse proxy header '{_reverseProxyHeader}' or unable to parse remote ip : " + context.Request.Headers[_reverseProxyHeader],
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