require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const jwt = require('jsonwebtoken');
const fetch = globalThis.fetch;
const { createClient } = require('@supabase/supabase-js');
const { buildResponse } = require('../shared/responseHandler');

const JWT_SECRET = process.env.JWT_SECRET;
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

const SERVICES = {
    users:   process.env.USERS_URL || 'http://localhost:3001',
    groups:  process.env.GROUPS_URL || 'http://localhost:3002',
    tickets: process.env.TICKETS_URL || 'http://localhost:3003'
};

// -------------------------------------------------------
// CORS
// -------------------------------------------------------
// -------------------------------------------------------
// CORS
// -------------------------------------------------------
fastify.register(require('@fastify/cors'), {
    origin: process.env.FRONTEND_URL 
        ? [process.env.FRONTEND_URL, 'http://localhost:4200'] 
        : true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
});

// -------------------------------------------------------
// RATE LIMITING
// -------------------------------------------------------
fastify.register(require('@fastify/rate-limit'), {
    max: 100,
    timeWindow: '1 minute',
    errorResponseBuilder: () => buildResponse(429, 'SxGW429', {
        message: 'Demasiadas solicitudes. Intenta de nuevo en un momento.'
    })
});

// -------------------------------------------------------
// HELPER — verificar JWT
// -------------------------------------------------------
function verificarToken(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    try {
        return jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    } catch {
        return null;
    }
}

// -------------------------------------------------------
// HELPER — verificar permiso en BD
// El usuario puede tener el permiso ligado a CUALQUIER grupo.
// Para rutas que no necesitan grupo específico (group:manage, user:manage),
// basta con que tenga ese permiso en al menos un grupo.
// -------------------------------------------------------
function tienePermiso(usuario, grupo_id, permiso_requerido) {
    const todosLosPermisos = usuario.permisos || { global: [], grupos: {} };
    
    // 1. ¿Tiene el permiso a nivel Global? (Aplica para todo el sistema)
    const tieneGlobal = todosLosPermisos.global.includes(permiso_requerido);
    if (tieneGlobal) return true;

    // 2. ¿Tiene el permiso en el grupo específico?
    if (grupo_id) {
        const permisosDelGrupo = todosLosPermisos.grupos[String(grupo_id)] || [];
        return permisosDelGrupo.includes(permiso_requerido);
    }

    return false;
}

// -------------------------------------------------------
// HELPER — proxy hacia microservicio
// -------------------------------------------------------
async function proxyRequest(reply, serviceUrl, path, request) {
    try {
        const url = `${serviceUrl}${path}`;
        const headers = { 'Authorization': request.headers.authorization || '' };

        const options = { method: request.method, headers };

        // Solo añadir Content-Type y Body si hay datos reales
        if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method) && request.body && Object.keys(request.body).length > 0) {
            headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(request.body);
        }

        const response = await fetch(url, options);
        const data = await response.json();
        reply.code(response.status).send(data);
    } catch (err) {
        reply.code(502).send(buildResponse(502, 'SxGW502', { message: 'Servicio no disponible.' }));
    }
}

// -------------------------------------------------------
// MATRIZ DE PERMISOS POR ENDPOINT
// -------------------------------------------------------
const PERMISOS_REQUERIDOS = {
    // --- TICKETS ---
    'POST /tickets':                          { permiso: 'ticket:add',        necesitaGrupo: true  },
    'PATCH /tickets/:id':                     { permiso: 'ticket:edit',       necesitaGrupo: true  },
    'PATCH /tickets/:id/status':              { permiso: 'ticket:edit:state', necesitaGrupo: true  },
    'DELETE /tickets/:id':                    { permiso: 'ticket:delete',     necesitaGrupo: true  },
    'POST /tickets/:id/comments':             { permiso: 'ticket:edit:comment', necesitaGrupo: true },
    'DELETE /tickets/:id/comments/:comentario_id': { permiso: 'ticket:edit:comment', necesitaGrupo: true },
    
    // --- GRUPOS ---
    'GET /groups/all':                        { permiso: 'group:manage',  necesitaGrupo: false },
    'POST /groups':                           { permiso: 'group:add',     necesitaGrupo: false },
    'PATCH /groups/:id':                      { permiso: 'group:manage',  necesitaGrupo: false }, // Cambiado de view a manage
    'POST /groups/:id/members':               { permiso: 'group:manage',  necesitaGrupo: false }, // Cambiado a manage
    'DELETE /groups/:id':                     { permiso: 'group:delete',  necesitaGrupo: false }, 
    'DELETE /groups/:id/members/:usuario_id': { permiso: 'group:manage',  necesitaGrupo: false }, // Cambiado a manage
    'POST /groups/:id/permissions':           { permiso: 'group:manage',  necesitaGrupo: false }, // Cambiado a manage
    'DELETE /groups/:id/permissions':         { permiso: 'group:manage',  necesitaGrupo: false }, // Cambiado a manage
    
    // --- USUARIOS ---
    'GET /users':                             { permiso: 'user:view',     necesitaGrupo: false },
    'DELETE /users/:id':                      { permiso: 'user:manage',   necesitaGrupo: false },
    'GET /users/:id/groups':                  { permiso: 'user:manage',   necesitaGrupo: false },
    'GET /users/:id/permissions':             { permiso: 'user:manage',   necesitaGrupo: false },
    'POST /users/:id/permissions':            { permiso: 'user:manage',   necesitaGrupo: false },
    'DELETE /users/:id/permissions':          { permiso: 'user:manage',   necesitaGrupo: false },
};

// -------------------------------------------------------
// HELPER — normalizar URL comparando contra patrones conocidos
// Evita el problema de reemplazar TODOS los segmentos por /:id
// y perder los nombres reales como /:usuario_id
// -------------------------------------------------------
function normalizarUrl(url) {
    return url
        .split('?')[0]
        .replace(/\/\d+\/members\/\d+/g, '/:id/members/:usuario_id')
        .replace(/\/\d+\/permissions\/\d+/g, '/:id/permissions/:usuario_id')
        .replace(/\/\d+\/permissions/g, '/:id/permissions')
        .replace(/\/\d+\/members/g, '/:id/members')
        .replace(/\/\d+\/comments\/\d+/g, '/:id/comments/:comentario_id')
        .replace(/\/\d+\/comments/g, '/:id/comments')
        .replace(/\/\d+\/status/g, '/:id/status')
        .replace(/\/\d+/g, '/:id');
}

// -------------------------------------------------------
// HOOK PRINCIPAL DE SEGURIDAD
// -------------------------------------------------------
fastify.addHook('preHandler', async (request, reply) => {
    const rutasPublicas = ['/auth/login', '/auth/register', '/health'];
    if (rutasPublicas.some(r => request.url.startsWith(r))) return;

    const usuario = verificarToken(request.headers.authorization);
    if (!usuario) {
        reply.code(401);
        return reply.send(buildResponse(401, 'SxGW401', { message: 'Token no proporcionado.' }));
    }

    request.usuario = usuario;

    const urlNormalizada = normalizarUrl(request.url);
    const clavePermiso = `${request.method} ${urlNormalizada}`;
    const reglaPermiso = PERMISOS_REQUERIDOS[clavePermiso];

    if (reglaPermiso) {
        const grupo_id = reglaPermiso.necesitaGrupo
            ? (request.body?.grupo_id || request.params?.grupo_id || request.query?.grupo_id || null)
            : null;

        const tiene = tienePermiso(usuario, grupo_id, reglaPermiso.permiso);

        if (!tiene) {
            reply.code(403);
            return reply.send(buildResponse(403, 'SxGW403', {
                message: `Acceso denegado. Se requiere: ${reglaPermiso.permiso}`
            }));
        }
    }
});

// -------------------------------------------------------
// HOOK PARA LOGS Y MÉTRICAS (Guardar en B.D.)
// -------------------------------------------------------
fastify.addHook('onResponse', async (request, reply) => {
    // 1. Recopilar datos de la petición
    const endpoint = normalizarUrl(request.url); // Usamos tu función normalizadora
    const metodo = request.method;
    const ip = request.ip;
    const status_http = reply.statusCode;
    const usuario_id = request.usuario ? request.usuario.sub : null;
    const tiempo_ms = reply.elapsedTime; // Fastify nos da el tiempo exacto en milisegundos

    // Ignorar las peticiones OPTIONS (CORS) y el /health para no llenar la BD de basura
    if (metodo === 'OPTIONS' || endpoint === '/health') return;

    try {
        // ==========================================
        // REQUERIMIENTO A: GUARDAR LOG
        // ==========================================
        let error_stack = null;
        // Si el status es 500 o mayor, intentamos extraer el error
        if (status_http >= 500 && reply.raw.payload) {
            error_stack = JSON.stringify(reply.raw.payload); 
        }

        await supabase.from('logs_sistema').insert([{
            endpoint,
            metodo,
            usuario_id,
            ip,
            status_http,
            error_stack
        }]);

        // ==========================================
        // REQUERIMIENTO B: ACTUALIZAR MÉTRICAS
        // ==========================================
        
        // 1. Buscar si ya existe la métrica para este endpoint
        const { data: metricaActual } = await supabase
            .from('metricas_api')
            .select('*')
            .eq('endpoint', endpoint)
            .eq('metodo', metodo)
            .maybeSingle();

        if (metricaActual) {
            // Calcular nuevo promedio: ( (PromedioAnterior * TotalAnterior) + NuevoTiempo ) / NuevoTotal
            const nuevoTotal = metricaActual.total_requests + 1;
            const nuevoPromedio = ((metricaActual.tiempo_promedio_ms * metricaActual.total_requests) + tiempo_ms) / nuevoTotal;

            await supabase
                .from('metricas_api')
                .update({
                    total_requests: nuevoTotal,
                    tiempo_promedio_ms: nuevoPromedio,
                    ultima_actualizacion: new Date().toISOString()
                })
                .eq('id', metricaActual.id);
        } else {
            // Si es la primera vez que se llama a este endpoint, lo insertamos
            await supabase
                .from('metricas_api')
                .insert([{
                    endpoint,
                    metodo,
                    total_requests: 1,
                    tiempo_promedio_ms: tiempo_ms
                }]);
        }

    } catch (err) {
        // Usamos console.error para no romper el flujo principal si falla la BD de logs
        console.error('Error al guardar log/métrica:', err.message);
    }
});

// -------------------------------------------------------
// RUTAS PÚBLICAS
// -------------------------------------------------------
fastify.get('/health', async (request, reply) => {
    return buildResponse(200, 'SxGW200', {
        message: 'API Gateway funcionando correctamente.' });
});

fastify.post('/auth/register', async (request, reply) => {
    await proxyRequest(reply, SERVICES.users, '/auth/register', request);
});

fastify.post('/auth/login', async (request, reply) => {
    await proxyRequest(reply, SERVICES.users, '/auth/login', request);
});

// -------------------------------------------------------
// RUTAS DE USUARIOS
// -------------------------------------------------------
fastify.get('/users/:id/permissions', async (request, reply) => {
    await proxyRequest(reply, SERVICES.users, `/users/${request.params.id}/permissions`, request);
});

fastify.post('/users/:id/permissions', async (request, reply) => {
    await proxyRequest(reply, SERVICES.users, `/users/${request.params.id}/permissions`, request);
});

fastify.delete('/users/:id/permissions', async (request, reply) => {
    await proxyRequest(reply, SERVICES.users, `/users/${request.params.id}/permissions`, request);
});

fastify.get('/users/:usuario_id/groups', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, `/users/${request.params.usuario_id}/groups`, request);
});

// 2. RUTAS GENÉRICAS (Deben ir DESPUÉS)
fastify.get('/users', async (request, reply) => {
    await proxyRequest(reply, SERVICES.users, '/users', request);
});

fastify.get('/users/:id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.users, `/users/${request.params.id}`, request);
});

fastify.patch('/users/:id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.users, `/users/${request.params.id}`, request);
});

fastify.delete('/users/:id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.users, `/users/${request.params.id}`, request);
});

// -------------------------------------------------------
// RUTAS DE GRUPOS
// -------------------------------------------------------
fastify.get('/groups/all', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, '/groups/all', request);
});

fastify.get('/groups', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, '/groups', request);
});

fastify.get('/groups/:id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, `/groups/${request.params.id}`, request);
});

fastify.post('/groups', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, '/groups', request);
});

fastify.patch('/groups/:id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, `/groups/${request.params.id}`, request);
});

fastify.delete('/groups/:id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, `/groups/${request.params.id}`, request);
});

fastify.post('/groups/:id/members', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, `/groups/${request.params.id}/members`, request);
});

fastify.delete('/groups/:id/members/:usuario_id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, `/groups/${request.params.id}/members/${request.params.usuario_id}`, request);
});

fastify.post('/groups/:id/permissions', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, `/groups/${request.params.id}/permissions`, request);
});

fastify.delete('/groups/:id/permissions', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, `/groups/${request.params.id}/permissions`, request);
});

fastify.get('/groups/:id/permissions/:usuario_id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.groups, `/groups/${request.params.id}/permissions/${request.params.usuario_id}`, request);
});

// -------------------------------------------------------
// RUTAS DE TICKETS
// -------------------------------------------------------
fastify.get('/tickets/group/:grupo_id', async (request, reply) => {
    const query = new URLSearchParams(request.query).toString();
    const path = `/tickets/group/${request.params.grupo_id}${query ? '?' + query : ''}`;
    await proxyRequest(reply, SERVICES.tickets, path, request);
});

fastify.get('/tickets/:id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.tickets, `/tickets/${request.params.id}`, request);
});

fastify.post('/tickets', async (request, reply) => {
    await proxyRequest(reply, SERVICES.tickets, '/tickets', request);
});

fastify.patch('/tickets/:id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.tickets, `/tickets/${request.params.id}`, request);
});

fastify.patch('/tickets/:id/status', async (request, reply) => {
    await proxyRequest(reply, SERVICES.tickets, `/tickets/${request.params.id}/status`, request);
});

fastify.delete('/tickets/:id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.tickets, `/tickets/${request.params.id}`, request);
});

fastify.post('/tickets/:id/comments', async (request, reply) => {
    await proxyRequest(reply, SERVICES.tickets, `/tickets/${request.params.id}/comments`, request);
});

fastify.delete('/tickets/:id/comments/:comentario_id', async (request, reply) => {
    await proxyRequest(reply, SERVICES.tickets, `/tickets/${request.params.id}/comments/${request.params.comentario_id}`, request);
});

// -------------------------------------------------------
// START
// -------------------------------------------------------
const start = async () => {
    try {
        await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
        console.log(`API Gateway activo en puerto ${process.env.PORT || 3000}`);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};
start();