require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const proxy = require('@fastify/http-proxy');
const { createClient } = require('@supabase/supabase-js');
const { buildResponse } = require('../shared/responseHandler');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// --- RATE LIMITING ---
fastify.register(require('@fastify/rate-limit'), {
    max: 100,
    timeWindow: '1 minute',
    errorResponseBuilder: (request, context) => buildResponse(429, 'SxGW429', { message: 'Too many requests' })
});

// --- PROXIES ---
fastify.register(proxy, { upstream: 'http://localhost:3001', prefix: '/users-service', rewritePrefix: '' });
fastify.register(proxy, { upstream: 'http://localhost:3002', prefix: '/groups-service', rewritePrefix: '' });
fastify.register(proxy, { upstream: 'http://localhost:3003', prefix: '/tickets-service', rewritePrefix: '' });

// --- LÓGICA DE SEGURIDAD: VERIFICACIÓN DE PERMISOS ---
async function checkPermission(userId, grupoId, permisoRequerido) {
    if (!grupoId || !permisoRequerido) return true; // Rutas globales (como login) no requieren grupo

    // El SuperAdmin de un módulo tiene el sufijo :manage
    const modulo = permisoRequerido.split(':')[0]; // ej: 'ticket'
    const permisoManage = `${modulo}:manage`;

    const { data, error } = await supabase
        .from('grupo_usuario_permisos')
        .select(`
            permisos!inner (
                nombre
            )
        `)
        .eq('usuario_id', userId)
        .eq('grupo_id', grupoId)
        .or(`nombre.eq.${permisoRequerido},nombre.eq.${permisoManage}`);

    return data && data.length > 0;
}

// --- HOOK DE SEGURIDAD (PRE-HANDLER) ---
fastify.addHook('preHandler', async (request, reply) => {
    const isAuthRoute = request.url.includes('/auth/login') || request.url.includes('/auth/register');
    if (isAuthRoute) return;

    const authHeader = request.headers.authorization;
    if (!authHeader) {
        reply.code(401);
        return buildResponse(401, 'SxGW401', { message: 'Token no proporcionado' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // 1. Validar Token en Supabase
        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError || !user) {
            reply.code(403);
            return buildResponse(403, 'SxGW403', { message: 'Token inválido o expirado' });
        }
        request.user = user;

        // 2. MATRIZ DE PERMISOS (Asocia rutas con permisos específicos)
        const permissionsMatrix = {
            // TICKETS
            '/tickets/create': 'ticket:add',
            '/tickets/edit': 'ticket:edit',
            '/tickets/status': 'ticket:edit:state',
            '/tickets/comment': 'ticket:edit:comment',
            '/tickets/delete': 'ticket:delete',
            '/tickets/group': 'ticket:view',
            // GROUPS
            '/groups/all': 'group:view',
            '/groups/edit': 'group:edit',
            '/groups/delete': 'group:delete',
            '/groups/permissions': 'group:manage',
            // USERS
            '/users': 'user:view'
        };

        // Encontrar si la ruta actual requiere un permiso
        const matchedRoute = Object.keys(permissionsMatrix).find(route => request.url.includes(route));

        if (matchedRoute) {
            const requiredPermission = permissionsMatrix[matchedRoute];
            
            // Extraer grupo_id (puede estar en params, body o query)
            const grupoId = request.body?.grupo_id || request.params?.grupo_id || request.params?.id || request.query?.grupo_id;

            // Si es una ruta que depende de un grupo, validamos permiso
            if (grupoId) {
                const hasAccess = await checkPermission(user.id, grupoId, requiredPermission);
                if (!hasAccess) {
                    reply.code(403);
                    return buildResponse(403, 'SxGW403', { 
                        message: `Acceso denegado. Requiere: ${requiredPermission} o ${requiredPermission.split(':')[0]}:manage` 
                    });
                }
            }
        }
    } catch (err) {
        reply.code(500);
        return buildResponse(500, 'SxGW500', { message: 'Error interno de seguridad' });
    }
});

// --- RUTAS PÚBLICAS DEL GATEWAY ---

// AUTH
fastify.post('/auth/register', async (req, res) => {
    const result = await fastify.inject({ method: 'POST', url: '/users-service/auth/register', payload: req.body });
    res.code(result.statusCode).send(result.json());
});

fastify.post('/auth/login', async (req, res) => {
    const result = await fastify.inject({ method: 'POST', url: '/users-service/auth/login', payload: req.body });
    res.code(result.statusCode).send(result.json());
});

// USERS
fastify.get('/users', async (req, res) => {
    const result = await fastify.inject({ method: 'GET', url: '/users-service/users', headers: req.headers });
    res.code(result.statusCode).send(result.json());
});

// GROUPS (Simplificado con un loop o inyecciones directas)
const groupRoutes = [
    { method: 'GET', path: '/groups/all', target: '/groups-service/groups/all' },
    { method: 'POST', path: '/groups/create', target: '/groups-service/groups/create' },
    { method: 'PATCH', path: '/groups/edit/:id', target: '/groups-service/groups/edit/' },
    { method: 'DELETE', path: '/groups/delete/:id', target: '/groups-service/groups/delete/' },
    { method: 'POST', path: '/groups/permissions', target: '/groups-service/groups/permissions' }
];

groupRoutes.forEach(route => {
    fastify[route.method.toLowerCase()](route.path, async (req, res) => {
        const url = route.path.includes(':id') ? route.target + req.params.id : route.target;
        const payload = req.body ? JSON.stringify(req.body) : null;
        const result = await fastify.inject({
            method: route.method,
            url: url,
            headers: { ...req.headers, 'content-length': payload ? Buffer.byteLength(payload).toString() : undefined },
            payload
        });
        res.code(result.statusCode).send(result.json());
    });
});

// TICKETS (Misma lógica de inyección)
const ticketRoutes = [
    { method: 'POST', path: '/tickets/create', target: '/tickets-service/tickets/create' },
    { method: 'PATCH', path: '/tickets/edit/:id', target: '/tickets-service/tickets/edit/' },
    { method: 'PATCH', path: '/tickets/status/:id', target: '/tickets-service/tickets/status/' },
    { method: 'DELETE', path: '/tickets/delete/:id', target: '/tickets-service/tickets/delete/' },
    { method: 'POST', path: '/tickets/comment', target: '/tickets-service/tickets/comment' },
    { method: 'GET', path: '/tickets/group/:grupo_id', target: '/tickets-service/tickets/group/' }
];

ticketRoutes.forEach(route => {
    fastify[route.method.toLowerCase()](route.path, async (req, res) => {
        const id = req.params.id || req.params.grupo_id;
        const url = id ? route.target + id : route.target;
        const payload = req.body ? JSON.stringify(req.body) : null;
        const result = await fastify.inject({
            method: route.method,
            url: url,
            headers: { ...req.headers, 'content-length': payload ? Buffer.byteLength(payload).toString() : undefined },
            payload
        });
        res.code(result.statusCode).send(result.json());
    });
});

// --- INICIO ---
const start = async () => {
    try {
        await fastify.listen({ port: process.env.PORT || 3000 });
        console.log(`API Gateway RBAC activo en puerto 3000`);
    } catch (err) {
        process.exit(1);
    }
};
start();