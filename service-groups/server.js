// RP_Backend/service-groups/server.js
require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const { buildResponse } = require('../shared/responseHandler');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

fastify.register(require('@fastify/cors'), { origin: true });

// =======================================================
// SCHEMAS DE VALIDACIÓN (AJV nativo de Fastify)
// =======================================================

const createGroupSchema = {
    body: {
        type: 'object',
        required: ['nombre'],
        properties: {
            nombre: { type: 'string', minLength: 3 },
            descripcion: { type: ['string', 'null'] }
        }
    }
};

const updateGroupSchema = {
    body: {
        type: 'object',
        properties: {
            nombre: { type: 'string', minLength: 3 },
            descripcion: { type: ['string', 'null'] }
        }
    }
};

const addMemberSchema = {
    body: {
        type: 'object',
        required: ['usuario_id'],
        properties: {
            usuario_id: { type: 'integer' }
        }
    }
};

const permissionSchema = {
    body: {
        type: 'object',
        required: ['usuario_id', 'permiso_nombre'],
        properties: {
            usuario_id: { type: 'integer' },
            permiso_nombre: { type: 'string', minLength: 3 }
        }
    }
};

// Interceptor global para errores de validación de JSON Schema
fastify.setErrorHandler(function (error, request, reply) {
    if (error.validation) {
        reply.code(400).send(buildResponse(400, 'SxGR400', {
            message: `Error de validación: ${error.message}`
        }));
    } else {
        reply.send(error);
    }
});


// -------------------------------------------------------
// HELPER — verificar token JWT
// -------------------------------------------------------
function verificarToken(request) {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
    try {
        return jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    } catch {
        return null;
    }
}

// -------------------------------------------------------
// HEALTH CHECK
// -------------------------------------------------------
fastify.get('/health', async (request, reply) => {
    return buildResponse(200, 'SxGR200', {
        message: 'Servicio de grupos funcionando correctamente.'
    });
});

// -------------------------------------------------------
// GET — grupos del usuario autenticado
// -------------------------------------------------------
fastify.get('/groups', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    try {
        const { data: memberships, error: memError } = await supabase
            .from('grupo_miembros')
            .select('grupo_id')
            .eq('usuario_id', usuario.sub);

        if (memError) throw memError;

        if (!memberships || memberships.length === 0) {
            return buildResponse(200, 'SxGR200', []);
        }

        const groupIds = memberships.map(m => m.grupo_id);

        const { data: grupos, error: groupsError } = await supabase
            .from('grupos')
            .select('id, nombre, descripcion, creador_id, creado_en')
            .in('id', groupIds);

        if (groupsError) throw groupsError;

        return buildResponse(200, 'SxGR200', grupos || []);

    } catch (err) {
        console.error('Error GET /groups:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error al obtener grupos.' });
    }
});

// -------------------------------------------------------
// GET — todos los grupos (solo para user:manage)
// -------------------------------------------------------
fastify.get('/groups/all', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    try {
        const { data: grupos, error } = await supabase
            .from('grupos')
            .select('id, nombre, descripcion, creador_id, creado_en')
            .order('creado_en', { ascending: false });

        if (error) throw error;

        return buildResponse(200, 'SxGR200', grupos || []);

    } catch (err) {
        console.error('Error GET /groups/all:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error al obtener grupos.' });
    }
});

// -------------------------------------------------------
// GET — un grupo por ID con sus miembros
// -------------------------------------------------------
fastify.get('/groups/:id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    const { id } = request.params;

    try {
        const { data: grupo, error } = await supabase
            .from('grupos')
            .select('id, nombre, descripcion, creador_id, creado_en')
            .eq('id', id)
            .maybeSingle();

        if (error || !grupo) {
            reply.code(404);
            return buildResponse(404, 'SxGR404', { message: 'Grupo no encontrado.' });
        }

        const { data: miembros } = await supabase
            .from('grupo_miembros')
            .select(`
                fecha_unido,
                usuarios ( id, nombre_completo, username, email )
            `)
            .eq('grupo_id', id);

        return buildResponse(200, 'SxGR200', {
            ...grupo,
            miembros: miembros || []
        });

    } catch (err) {
        console.error('Error GET /groups/:id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error interno del servidor.' });
    }
});

// -------------------------------------------------------
// POST — crear grupo (con Schema)
// -------------------------------------------------------
fastify.post('/groups', { schema: createGroupSchema }, async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    const { nombre, descripcion } = request.body;

    try {
        const { data: nuevoGrupo, error: groupError } = await supabase
            .from('grupos')
            .insert([{
                nombre,
                descripcion: descripcion || null,
                creador_id: usuario.sub
            }])
            .select()
            .single();

        if (groupError) throw groupError;

        // Agregar al creador como miembro automáticamente
        await supabase
            .from('grupo_miembros')
            .insert([{ grupo_id: nuevoGrupo.id, usuario_id: usuario.sub }]);

        reply.code(201);
        return buildResponse(201, 'SxGR201', {
            message: 'Grupo creado correctamente.',
            grupo: nuevoGrupo
        });

    } catch (err) {
        console.error('Error POST /groups:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error al crear el grupo.' });
    }
});

// -------------------------------------------------------
// PATCH — editar grupo (con Schema)
// -------------------------------------------------------
fastify.patch('/groups/:id', { schema: updateGroupSchema }, async (request, reply) => {
    const usuario = verificarToken(request);
    const { id } = request.params;

    if (Object.keys(request.body).length === 0) {
        return reply.code(400).send(buildResponse(400, 'SxGR400', { message: 'No hay datos para actualizar.' }));
    }

    try {
        const { data: grupo } = await supabase.from('grupos').select('creador_id').eq('id', id).single();
        const esDuenio = grupo.creador_id === usuario.sub;
        const esAdminGlobal = usuario.permisos?.global.includes('group:edit');

        if (!esDuenio && !esAdminGlobal) {
            return reply.code(403).send(buildResponse(403, 'SxGR403', { message: 'Sin permiso global ni de propietario.' }));
        }

        const { data: actualizado } = await supabase.from('grupos').update(request.body).eq('id', id).select().single();
        return buildResponse(200, 'SxGR200', { message: 'Actualizado', grupo: actualizado });
    } catch (err) { 
        reply.code(500).send(buildResponse(500, 'SxGR500', { message: 'Error' })); 
    }
});

// -------------------------------------------------------
// DELETE — eliminar grupo
// -------------------------------------------------------
fastify.delete('/groups/:id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario.permisos?.global.includes('group:delete')) {
        return reply.code(403).send(buildResponse(403, 'SxGR403', { message: 'Requiere permiso de borrado global.' }));
    }

    try {
        await supabase.from('grupos').delete().eq('id', request.params.id);
        return buildResponse(200, 'SxGR200', { message: 'Grupo eliminado' });
    } catch (err) { reply.code(500).send(buildResponse(500, 'SxGR500', { message: 'Error' })); }
});

// -------------------------------------------------------
// POST — agregar miembro a grupo (con Schema)
// -------------------------------------------------------
fastify.post('/groups/:id/members', { schema: addMemberSchema }, async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) return reply.code(401).send(buildResponse(401, 'SxGR401', { message: 'Token inválido.' }));

    const { id } = request.params;
    const { usuario_id } = request.body;

    try {
        const { data: grupo } = await supabase.from('grupos').select('creador_id').eq('id', id).single();
        const esDuenio = grupo.creador_id === usuario.sub;
        const esAdminGlobal = usuario.permisos?.global.includes('group:manage');

        if (!esDuenio && !esAdminGlobal) {
            return reply.code(403).send(buildResponse(403, 'SxGR403', { message: 'Solo el creador o un Admin pueden añadir miembros.' }));
        }

        await supabase.from('grupo_miembros').insert([{ grupo_id: id, usuario_id }]);
        return buildResponse(201, 'SxGR201', { message: 'Miembro agregado' });
    } catch (err) { 
        if(err.code === '23505') return reply.code(400).send(buildResponse(400, 'SxGR400', { message: 'El usuario ya es miembro.' }));
        reply.code(500).send(buildResponse(500, 'SxGR500', { message: 'Error' })); 
    }
});

// -------------------------------------------------------
// DELETE — remover miembro de grupo
// -------------------------------------------------------
fastify.delete('/groups/:id/members/:usuario_id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) return reply.code(401).send(buildResponse(401, 'SxGR401', { message: 'Token inválido.' }));

    const { id, usuario_id } = request.params;

    try {
        const { data: grupo } = await supabase.from('grupos').select('creador_id').eq('id', id).single();
        const esDuenio = grupo.creador_id === usuario.sub;
        const esAdminGlobal = usuario.permisos?.global.includes('group:manage');

        if (!esDuenio && !esAdminGlobal) {
            return reply.code(403).send(buildResponse(403, 'SxGR403', { message: 'Solo el creador o un Admin pueden remover miembros.' }));
        }

        if (grupo.creador_id === Number(usuario_id)) {
             return reply.code(400).send(buildResponse(400, 'SxGR400', { message: 'El creador no puede ser removido del grupo.' }));
        }

        await supabase.from('grupo_miembros').delete().eq('grupo_id', id).eq('usuario_id', usuario_id);
        return buildResponse(200, 'SxGR200', { message: 'Miembro removido' });
    } catch (err) { reply.code(500).send(buildResponse(500, 'SxGR500', { message: 'Error' })); }
});

// -------------------------------------------------------
// POST — asignar permiso a usuario en grupo (con Schema)
// -------------------------------------------------------
fastify.post('/groups/:id/permissions', { schema: permissionSchema }, async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) return reply.code(401).send(buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' }));

    const { id } = request.params;
    const { usuario_id, permiso_nombre } = request.body;

    try {
        const { data: grupo } = await supabase.from('grupos').select('creador_id').eq('id', id).single();
        const esDuenio = grupo.creador_id === usuario.sub;
        const esAdminGlobal = usuario.permisos?.global.includes('group:manage') || usuario.permisos?.global.includes('user:manage');

        if (!esDuenio && !esAdminGlobal) {
            return reply.code(403).send(buildResponse(403, 'SxGR403', { message: 'Solo el creador del grupo puede asignar permisos.' }));
        }

        const { data: permiso, error: permisoError } = await supabase
            .from('permisos')
            .select('id')
            .eq('nombre', permiso_nombre)
            .maybeSingle();

        if (permisoError || !permiso) return reply.code(404).send(buildResponse(404, 'SxGR404', { message: `Permiso '${permiso_nombre}' no existe.` }));

        const { data, error } = await supabase
            .from('grupo_usuario_permisos')
            .insert([{ grupo_id: id, usuario_id, permiso_id: permiso.id }])
            .select()
            .single();

        if (error) {
            if (error.code === '23505') return reply.code(400).send(buildResponse(400, 'SxGR400', { message: 'El usuario ya tiene ese permiso en este grupo.' }));
            throw error;
        }

        return reply.code(201).send(buildResponse(201, 'SxGR201', { message: 'Permiso asignado correctamente.', data }));

    } catch (err) {
        reply.code(500).send(buildResponse(500, 'SxGR500', { message: 'Error al asignar permiso.' }));
    }
});

// -------------------------------------------------------
// DELETE — revocar permiso a usuario en grupo
// -------------------------------------------------------
fastify.delete('/groups/:id/permissions', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) return reply.code(401).send(buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' }));

    const { id } = request.params;
    const body = request.body || {};
    const usuario_id   = body.usuario_id   || request.query?.usuario_id;
    const permiso_nombre = body.permiso_nombre || request.query?.permiso_nombre;

    if (!usuario_id || !permiso_nombre) {
        return reply.code(400).send(buildResponse(400, 'SxGR400', { message: 'usuario_id y permiso_nombre son obligatorios.' }));
    }

    try {
        const { data: grupo } = await supabase.from('grupos').select('creador_id').eq('id', id).single();
        const esDuenio = grupo.creador_id === usuario.sub;
        const esAdminGlobal = usuario.permisos?.global.includes('group:manage') || usuario.permisos?.global.includes('user:manage');

        if (!esDuenio && !esAdminGlobal) {
            return reply.code(403).send(buildResponse(403, 'SxGR403', { message: 'Solo el creador del grupo puede remover permisos.' }));
        }

        const { data: permiso } = await supabase
            .from('permisos')
            .select('id')
            .eq('nombre', permiso_nombre)
            .maybeSingle();

        if (!permiso) return reply.code(404).send(buildResponse(404, 'SxGR404', { message: `Permiso '${permiso_nombre}' no existe.` }));

        const { error } = await supabase
            .from('grupo_usuario_permisos')
            .delete()
            .eq('grupo_id', id)
            .eq('usuario_id', usuario_id)
            .eq('permiso_id', permiso.id);

        if (error) throw error;

        return buildResponse(200, 'SxGR200', { message: 'Permiso revocado correctamente.' });

    } catch (err) {
        reply.code(500).send(buildResponse(500, 'SxGR500', { message: 'Error al revocar permiso.' }));
    }
});

// -------------------------------------------------------
// GET — permisos de un usuario en un grupo
// -------------------------------------------------------
fastify.get('/groups/:id/permissions/:usuario_id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    const { id, usuario_id } = request.params;

    try {
        const { data, error } = await supabase
            .from('grupo_usuario_permisos')
            .select('permisos ( id, nombre, descripcion )')
            .eq('grupo_id', id)
            .eq('usuario_id', usuario_id);

        if (error) throw error;

        const permisos = data.map(p => p.permisos);

        return buildResponse(200, 'SxGR200', permisos);

    } catch (err) {
        console.error('Error GET /groups/:id/permissions/:usuario_id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error al obtener permisos.' });
    }
});

fastify.get('/users/:usuario_id/groups', async (request, reply) => {
    const { usuario_id } = request.params;

    try {
        const { data, error } = await supabase
            .from('grupo_miembros')
            .select(`
                grupo_id,
                grupos ( id, nombre, descripcion )
            `)
            .eq('usuario_id', usuario_id);

        if (error) throw error;

        const gruposDelUsuario = data.map(item => item.grupos);

        return buildResponse(200, 'SxGR200', gruposDelUsuario);
    } catch (err) {
        return buildResponse(500, 'SxGR500', { message: 'Error al obtener grupos del usuario' });
    }
});

// -------------------------------------------------------
// START
// -------------------------------------------------------
const start = async () => {
    try {
        await fastify.listen({ port: process.env.PORT || 3002, host: '0.0.0.0' });
        console.log(`Servicio de Grupos activo en puerto ${process.env.PORT || 3002}`);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

start();