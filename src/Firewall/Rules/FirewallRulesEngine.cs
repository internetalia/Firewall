using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Http;

namespace Firewall
{
    /// <summary>
    /// Rules engine to configure Firewall rules for request filtering.
    /// </summary>
    public static class FirewallRulesEngine
    {
        /// <summary>
        /// Configures the Firewall to deny all access.
        /// <para>Use this as the base rule before configuring other rules.</para>
        /// </summary>
        public static IFirewallRule DenyAllAccess()
        {
            return new DenyAllRule();
        }

        /// <summary>
        /// Configures the Firewall to allow requests from localhost.
        /// </summary>
        public static IFirewallRule ExceptFromLocalhost(this IFirewallRule rule)
        {
            return new LocalhostRule(rule);
        }

        /// <summary>
        /// Configures the Firewall to allow requests from specific IP addresses.
        /// </summary>
        public static IFirewallRule ExceptFromIPAddresses(
            this IFirewallRule rule,
            IList<IPAddress> ipAddresses)
        {
            return new IPAddressRule(rule, ipAddresses);
        }

        /// <summary>
        /// Configures the Firewall to allow requests from IP addresses which belong to a list of specific IP address ranges.
        /// </summary>
        public static IFirewallRule ExceptFromIPAddressRanges(
            this IFirewallRule rule,
            IList<CIDRNotation> cidrNotations)
        {
            return new IPAddressRangeRule(rule, cidrNotations);
        }

        /// <summary>
        /// Configures the Firewall to allow requests from IP addresses which belong to Cloudflare.
        /// </summary>
        /// <param name="rule">Base rule which gets validated when the request did not come from Cloudflare.</param>
        /// <param name="ipv4ListUrl">URL which returns a list of all Cloudflare IPv4 address ranges.</param>
        /// <param name="ipv6ListUrl">URL which returns a list of all Cloudflare IPv6 address ranges.</param>
        public static IFirewallRule ExceptFromCloudflare(
            this IFirewallRule rule,
            string ipv4ListUrl = null,
            string ipv6ListUrl = null)
        {
            var helper = new CloudflareHelper(new HttpClient());
            var (ips, cidrs) = helper.GetIPAddressRangesAsync(ipv4ListUrl, ipv6ListUrl).Result;

            return new IPAddressRule(new IPAddressRangeRule(rule, cidrs), ips);
        }

        /// <summary>
        /// Configures the Firewall to allow requests from IP addresses which belong to Cloudflare.
        /// </summary>
        /// <param name="rule">Base rule which gets validated when the request did not come from Cloudflare.</param>
        /// <param name="allowedClientIPAddresses">The list of client ip addresses proxied through cloudflare</param>
        /// <param name="ipv4ListUrl">URL which returns a list of all Cloudflare IPv4 address ranges.</param>
        /// <param name="ipv6ListUrl">URL which returns a list of all Cloudflare IPv6 address ranges.</param>
        public static IFirewallRule ExceptFromCloudflareWithClientIPs(
            this IFirewallRule rule,
            List<IPAddress> allowedClientIPAddresses,
            string ipv4ListUrl = null,
            string ipv6ListUrl = null)
        {
            var helper = new CloudflareHelper(new HttpClient());
            var (ips, cidrs) = helper.GetIPAddressRangesAsync(ipv4ListUrl, ipv6ListUrl).Result;

            return new ReverseProxyClientIPAddressRule(new IPAddressRule(new IPAddressRangeRule(rule, cidrs), ips), allowedClientIPAddresses, "CF-Connecting-IP");
        }

        /// <summary>
        /// Configures the Firewall to allow requests from IP addresses as long as they are accessing a specific hostname. E.g. internal access to staging url
        /// </summary>
        /// <param name="rule">Base rule which gets validated when the client ip or hostname are not valid.</param>
        /// <param name="allowedClientIPAddresses">The list of valid client ip addresses</param>
        /// <param name="hostNamePartial">part of the hostname to check e.g. -staging.azurewebsites.net</param>
        public static IFirewallRule ExceptForHostnameFromClientIPs(
            this IFirewallRule rule,
            List<IPAddress> allowedClientIPAddresses,
            string hostNamePartial)
        {
            return new HostnameSpecificIPAddressRule(rule, allowedClientIPAddresses, hostNamePartial);
        }


        /// <summary>
        /// Configures the Firewall to allow requests from IP addresses proxied through Cloudflare.
        /// </summary>
        /// <param name="rule">Base rule which gets validated when the request did not come from Cloudflare or the client ip is not valid.</param>
        /// <param name="allowedClientIPAddressRanges">Address ranges of client ips proxied through cloudflare</param>
        /// <param name="ipv4ListUrl">URL which returns a list of all Cloudflare IPv4 address ranges.</param>
        /// <param name="ipv6ListUrl">URL which returns a list of all Cloudflare IPv6 address ranges.</param>
        public static IFirewallRule ExceptFromCloudflareAndClientIPRanges(
            this IFirewallRule rule,
            List<CIDRNotation> allowedClientIPAddressRanges,
            string ipv4ListUrl = null,
            string ipv6ListUrl = null)
        {
            var helper = new CloudflareHelper(new HttpClient());
            var (ips, cidrs) = helper.GetIPAddressRangesAsync(ipv4ListUrl, ipv6ListUrl).Result;

            return new ReverseProxyClientIPAddressRangeRule(new IPAddressRule(new IPAddressRangeRule(rule, cidrs), ips),allowedClientIPAddressRanges, "CF-Connecting-IP");
        }

        /// <summary>
        /// Configures the Firewall to allow requests from specific countries.
        /// </summary>
        public static IFirewallRule ExceptFromCountries(
            this IFirewallRule rule,
            IList<CountryCode> countries)
        {
            return new CountryRule(rule, countries);
        }

        /// <summary>
        /// Configures the Firewall to allow requests which satisfy a custom <paramref name="filter"/>.
        /// </summary>
        public static IFirewallRule ExceptWhen(
            this IFirewallRule rule,
            Func<HttpContext, bool> filter)
        {
            return new CustomRule(rule, filter);
        }
    }
}