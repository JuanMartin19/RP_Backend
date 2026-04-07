// RP_Backend/shared/responseHandler.js

/**
 * Genera el esquema de respuesta universal
 * @param {number} statusCode - Código HTTP (ej. 200, 400, 403)
 * @param {string} intOpCode - Código interno (ej. 'SxUS200')
 * @param {any} data - El payload de respuesta (array, objeto o null)
 */
function buildResponse(statusCode, intOpCode, data = null) {
  return {
    statusCode,
    intOpCode,
    data
  };
}

module.exports = { buildResponse };