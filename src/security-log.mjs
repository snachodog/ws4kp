// Lightweight, dependency-free security event logging.
//
// This is a single-container hobby deployment with no database and no log
// aggregation pipeline - stdout is already captured by Docker/Portainer logs,
// so a structured, greppable console line is sufficient. Not intended to grow
// into a logging framework.

/**
 * Log a security-relevant event (rejected input, cache eviction, etc.) as a single
 * structured JSON line on stdout, prefixed so it's easy to grep/alert on.
 *
 * @param {string} event short machine-readable event name, e.g. 'request-too-large'
 * @param {import('express').Request} [req] the request that triggered the event, if any
 * @param {object} [details] any additional structured detail to include
 */
const logSecurityEvent = (event, req, details = {}) => {
	const entry = {
		timestamp: new Date().toISOString(),
		event,
		ip: req?.ip,
		method: req?.method,
		path: req?.originalUrl || req?.url,
		...details,
	};
	console.warn(`🛡️ Security | ${JSON.stringify(entry)}`);
};

export default logSecurityEvent;
