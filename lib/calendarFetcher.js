'use strict';

const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const dns = require('node:dns');

const MAX_REDIRECTS = 10;

const noopLogger = { debug() {} };

function shouldIgnoreSSL(sslignore) {
    return sslignore === 'ignore' || sslignore === 'true' || sslignore === true;
}

/**
 * Check whether an IP literal is private, loopback or link-local.
 *
 * @param {string} ip IP literal
 * @returns {boolean} true if the address is private/internal
 */
function isPrivateIp(ip) {
    return (
        ip === '127.0.0.1' ||
        ip === '::1' ||
        ip === '0.0.0.0' ||
        /^10\./.test(ip) ||
        /^192\.168\./.test(ip) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
        /^169\.254\./.test(ip) ||
        /^f[cd][0-9a-f]{0,2}:/i.test(ip) ||
        /^fe80:/i.test(ip)
    );
}

/**
 * Resolve a hostname (or literal IP) to its IP address.
 *
 * @param {string} hostname hostname or IP literal
 * @returns {Promise<string>} resolved IP address
 */
async function resolveHostAddress(hostname) {
    const ip = net.isIP(hostname) ? hostname : (await dns.promises.lookup(hostname)).address;
    if (!net.isIP(ip)) {
        throw new Error(`Could not resolve a valid IP address for "${hostname}"`);
    }
    return ip;
}

/**
 * Check whether a hostname (or literal IP) resolves to a private, loopback or link-local address.
 *
 * @param {string} hostname hostname or IP literal
 * @returns {Promise<boolean>} true if the address is private/internal
 */
async function resolvesToPrivateAddress(hostname) {
    return isPrivateIp(await resolveHostAddress(hostname));
}

/**
 * Ensure a redirect does not downgrade protocol or switch to a non-http(s) scheme.
 *
 * @param {string} originalUrl URL that produced the redirect
 * @param {string} redirectUrl URL being redirected to
 */
function assertRedirectProtocolAllowed(originalUrl, redirectUrl) {
    const originalProtocol = new URL(originalUrl).protocol;
    const redirectProtocol = new URL(redirectUrl).protocol;
    if (!['http:', 'https:'].includes(redirectProtocol)) {
        throw new Error(`Invalid redirect protocol "${redirectProtocol}" for calendar "${originalUrl}"`);
    }
    if (originalProtocol === 'https:' && redirectProtocol === 'http:') {
        throw new Error(`Refuse HTTPS to HTTP redirect while fetching calendar from ${originalUrl}`);
    }
}

/**
 * Ensure a redirect destination is allowed. A redirect to the exact host the originally configured
 * URL resolved to is always allowed; a redirect to any other private/loopback/link-local address is
 * refused, regardless of whether the originally configured URL was itself private.
 *
 * @param {string} redirectUrl URL being redirected to
 * @param {string|null} trustedAddress IP address the originally configured calendar URL resolved to
 */
async function assertRedirectDestinationAllowed(redirectUrl, trustedAddress) {
    const hostname = new URL(redirectUrl).hostname;
    let ip;
    try {
        ip = await resolveHostAddress(hostname);
    } catch {
        // Fail closed: an unresolvable redirect target cannot be verified as safe.
        throw new Error(`Refusing to follow redirect to "${redirectUrl}": could not resolve destination address`);
    }
    if (trustedAddress && ip === trustedAddress) {
        return;
    }
    if (isPrivateIp(ip)) {
        throw new Error(`Refusing to follow redirect to "${redirectUrl}": resolves to a private/internal address`);
    }
}

/**
 * Request calendar data over HTTP(S) using the raw http/https modules, following redirects manually.
 * Used when the adapter is configured to ignore TLS verification errors.
 *
 * @param {string} url URL to request
 * @param {object} opts options
 * @param {Record<string, string>} opts.headers request headers
 * @param {string|boolean} opts.sslignore adapter SSL ignore flag
 * @param {string|null} opts.trustedAddress IP address the originally configured calendar URL resolved to
 * @param {object} opts.logger logger with a `debug` method
 * @param {number} opts.timeoutMs request timeout in milliseconds
 * @param {number} [redirectsLeft] how many redirects are still allowed
 * @returns {Promise<string>} response body as UTF-8 text
 */
function fetchViaHttp(url, { headers, sslignore, trustedAddress, logger, timeoutMs }, redirectsLeft = MAX_REDIRECTS) {
    return new Promise((resolve, reject) => {
        let settled = false;
        const rejectOnce = error => {
            if (settled) {
                return;
            }
            settled = true;
            reject(error);
        };
        const resolveOnce = value => {
            if (settled) {
                return;
            }
            settled = true;
            resolve(value);
        };

        if (redirectsLeft <= 0) {
            return rejectOnce(new Error(`Too many redirects while fetching calendar from ${url}`));
        }
        const requester = url.startsWith('https://') ? https : http;

        const request = requester.request(
            url,
            {
                method: 'GET',
                headers,
                rejectUnauthorized: !shouldIgnoreSSL(sslignore),
                timeout: timeoutMs,
            },
            response => {
                const chunks = [];
                response.on('data', chunk => chunks.push(chunk));
                response.on('end', async () => {
                    if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                        try {
                            const redirectUrl = new URL(response.headers.location, url).toString();
                            assertRedirectProtocolAllowed(url, redirectUrl);
                            await assertRedirectDestinationAllowed(redirectUrl, trustedAddress);
                            logger.debug(`Follow redirect for "${url}" to "${redirectUrl}"`);
                            const redirectBody = await fetchViaHttp(
                                redirectUrl,
                                { headers, sslignore, trustedAddress, logger, timeoutMs },
                                redirectsLeft - 1,
                            );
                            return resolveOnce(redirectBody);
                        } catch (error) {
                            return rejectOnce(error);
                        }
                    }

                    const body = Buffer.concat(chunks).toString('utf-8');
                    if (response.statusCode < 200 || response.statusCode >= 300) {
                        const error = new Error(`HTTP ${response.statusCode} when fetching calendar from ${url}`);
                        error.status = response.statusCode;
                        return rejectOnce(error);
                    }
                    resolveOnce(body);
                });
                response.on('error', rejectOnce);
            },
        );

        request.on('error', rejectOnce);
        request.on('timeout', () => {
            rejectOnce(new Error(`Request timeout after ${timeoutMs}ms when fetching calendar from ${url}`));
            request.destroy();
        });
        request.end();
    });
}

/**
 * Request calendar data using the global fetch() implementation, following redirects manually so each
 * hop's destination can be validated.
 *
 * @param {string} url URL to request
 * @param {object} opts options
 * @param {Record<string, string>} opts.headers request headers
 * @param {string|null} opts.trustedAddress IP address the originally configured calendar URL resolved to
 * @param {object} opts.logger logger with a `debug` method
 * @param {number} opts.timeoutMs request timeout in milliseconds
 * @param {typeof fetch} opts.fetchImpl fetch implementation to use (overridable for tests)
 * @returns {Promise<string>} response body as UTF-8 text
 */
async function fetchViaFetch(url, { headers, trustedAddress, logger, timeoutMs, fetchImpl }) {
    const abortController = new AbortController();
    const timeout = setTimeout(
        () =>
            abortController.abort(new Error(`Request timeout after ${timeoutMs}ms when fetching calendar from ${url}`)),
        timeoutMs,
    );
    try {
        let currentUrl = url;
        for (let redirectsLeft = MAX_REDIRECTS; ; redirectsLeft--) {
            const response = await fetchImpl(currentUrl, {
                method: 'GET',
                headers,
                redirect: 'manual',
                signal: abortController.signal,
            });

            const location = response.headers.get('location');
            if (response.status >= 300 && response.status < 400 && location) {
                if (redirectsLeft <= 0) {
                    throw new Error(`Too many redirects while fetching calendar from ${url}`);
                }
                const redirectUrl = new URL(location, currentUrl).toString();
                assertRedirectProtocolAllowed(currentUrl, redirectUrl);
                await assertRedirectDestinationAllowed(redirectUrl, trustedAddress);
                logger.debug(`Follow redirect for "${currentUrl}" to "${redirectUrl}"`);
                currentUrl = redirectUrl;
                continue;
            }

            if (!response.ok) {
                const error = new Error(
                    `HTTP ${response.status} (${response.statusText}) when fetching calendar from ${currentUrl}`,
                );
                error.status = response.status;
                throw error;
            }

            return await response.text();
        }
    } finally {
        clearTimeout(timeout);
    }
}

/**
 * Fetch calendar data from an http(s) URL, allowing explicitly configured internal/private calendar
 * URLs while validating every redirect hop so a public-looking configured URL cannot be redirected
 * into the internal network.
 *
 * @param {string} url calendar URL to fetch
 * @param {object} [opts] options
 * @param {Record<string, string>} [opts.headers] request headers
 * @param {string|boolean} [opts.sslignore] adapter SSL ignore flag
 * @param {number} [opts.timeoutMs] request timeout in milliseconds
 * @param {object} [opts.logger] logger with a `debug` method
 * @param {typeof fetch} [opts.fetchImpl] fetch implementation to use (overridable for tests)
 * @returns {Promise<string>} response body as UTF-8 text
 */
async function fetchCalendarUrl(url, opts = {}) {
    const { headers = {}, sslignore, timeoutMs = 30000, logger = noopLogger, fetchImpl = fetch } = opts;

    let trustedAddress = null;
    try {
        trustedAddress = await resolveHostAddress(new URL(url).hostname);
    } catch {
        // Unresolvable/unparseable initial host - let the real request surface its own error.
        trustedAddress = null;
    }

    if (shouldIgnoreSSL(sslignore)) {
        return fetchViaHttp(url, { headers, sslignore, trustedAddress, logger, timeoutMs });
    }
    return fetchViaFetch(url, { headers, trustedAddress, logger, timeoutMs, fetchImpl });
}

module.exports = {
    fetchCalendarUrl,
    resolvesToPrivateAddress,
    assertRedirectDestinationAllowed,
    assertRedirectProtocolAllowed,
};
