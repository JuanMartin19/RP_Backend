require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const { buildResponse } = require('../shared/responseHandler');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

fastify.register(require('@fastify/cors'), { origin: true });

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
        message: 'Servicio de grupos funcionando correctamente'
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
// POST — crear grupo
// -------------------------------------------------------
fastify.post('/groups', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    const { nombre, descripcion } = request.body || {};

    if (!nombre) {
        reply.code(400);
        return buildResponse(400, 'SxGR400', { message: 'El nombre del grupo es obligatorio.' });
    }

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
// PATCH — editar grupo
// -------------------------------------------------------
fastify.patch('/groups/:id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) return reply.code(401).send(buildResponse(401, 'SxGR401', { message: 'No autorizado' }));

    const { id } = request.params;
    // Limpiamos el body para que solo guarde lo que debe
    const updates = {};
    if (request.body.nombre) updates.nombre = request.body.nombre;
    if (request.body.descripcion !== undefined) updates.descripcion = request.body.descripcion;

    try {
        const { data: grupoActualizado, error } = await supabase
            .from('grupos')
            .update(updates)
            .eq('id', id)
            .select().single();

        if (error) return reply.code(404).send(buildResponse(404, 'SxGR404', { message: 'Grupo no encontrado.' }));

        return buildResponse(200, 'SxGR200', { message: 'Grupo actualizado', grupo: grupoActualizado });
    } catch (err) {
        reply.code(500).send(buildResponse(500, 'SxGR500', { message: 'Error interno' }));
    }
});

// -------------------------------------------------------
// DELETE — eliminar grupo
// -------------------------------------------------------
fastify.delete('/groups/:id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    const { id } = request.params;

    try {
        const { error } = await supabase
            .from('grupos')
            .delete()
            .eq('id', id);

        if (error) throw error;

        return buildResponse(200, 'SxGR200', {
            message: 'Grupo eliminado correctamente.'
        });

    } catch (err) {
        console.error('Error DELETE /groups/:id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error al eliminar el grupo.' });
    }
});

// -------------------------------------------------------
// POST — agregar miembro a grupo
// -------------------------------------------------------
fastify.post('/groups/:id/members', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    const { id } = request.params;
    const { usuario_id } = request.body || {};

    if (!usuario_id) {
        reply.code(400);
        return buildResponse(400, 'SxGR400', { message: 'usuario_id es obligatorio.' });
    }

    try {
        const { data: usuarioExiste } = await supabase
            .from('usuarios')
            .select('id')
            .eq('id', usuario_id)
            .maybeSingle();

        if (!usuarioExiste) {
            reply.code(404);
            return buildResponse(404, 'SxGR404', { message: 'Usuario no encontrado.' });
        }

        const { data, error } = await supabase
            .from('grupo_miembros')
            .insert([{ grupo_id: id, usuario_id }])
            .select()
            .single();

        if (error) {
            if (error.code === '23505') {
                reply.code(400);
                return buildResponse(400, 'SxGR400', { message: 'El usuario ya es miembro de este grupo.' });
            }
            throw error;
        }

        reply.code(201);
        return buildResponse(201, 'SxGR201', {
            message: 'Miembro agregado correctamente.',
            data
        });

    } catch (err) {
        console.error('Error POST /groups/:id/members:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error al agregar miembro.' });
    }
});

// -------------------------------------------------------
// DELETE — remover miembro de grupo
// FIX: usuario_id viene en params, NO en body
// -------------------------------------------------------
fastify.delete('/groups/:id/members/:usuario_id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    // usuario_id siempre viene en la URL — nunca del body
    const { id, usuario_id } = request.params;

    if (!id || !usuario_id) {
        reply.code(400);
        return buildResponse(400, 'SxGR400', { message: 'grupo_id y usuario_id son obligatorios.' });
    }

    try {
        const { error } = await supabase
            .from('grupo_miembros')
            .delete()
            .eq('grupo_id', id)
            .eq('usuario_id', usuario_id);

        if (error) throw error;

        return buildResponse(200, 'SxGR200', {
            message: 'Miembro removido correctamente.'
        });

    } catch (err) {
        console.error('Error DELETE /groups/:id/members/:usuario_id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error al remover miembro.' });
    }
});

// -------------------------------------------------------
// POST — asignar permiso a usuario en grupo
// -------------------------------------------------------
fastify.post('/groups/:id/permissions', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    const { id } = request.params;
    const { usuario_id, permiso_nombre } = request.body || {};

    if (!usuario_id || !permiso_nombre) {
        reply.code(400);
        return buildResponse(400, 'SxGR400', {
            message: 'usuario_id y permiso_nombre son obligatorios.'
        });
    }

    try {
        const { data: permiso, error: permisoError } = await supabase
            .from('permisos')
            .select('id')
            .eq('nombre', permiso_nombre)
            .maybeSingle();

        if (permisoError || !permiso) {
            reply.code(404);
            return buildResponse(404, 'SxGR404', { message: `Permiso '${permiso_nombre}' no existe.` });
        }

        const { data, error } = await supabase
            .from('grupo_usuario_permisos')
            .insert([{ grupo_id: id, usuario_id, permiso_id: permiso.id }])
            .select()
            .single();

        if (error) {
            if (error.code === '23505') {
                reply.code(400);
                return buildResponse(400, 'SxGR400', { message: 'El usuario ya tiene ese permiso en este grupo.' });
            }
            throw error;
        }

        reply.code(201);
        return buildResponse(201, 'SxGR201', {
            message: 'Permiso asignado correctamente.',
            data
        });

    } catch (err) {
        console.error('Error POST /groups/:id/permissions:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error al asignar permiso.' });
    }
});

// -------------------------------------------------------
// DELETE — revocar permiso a usuario en grupo
// FIX: Fastify puede recibir body vacío en DELETE — siempre usar || {}
// y leer también desde query params como fallback
// -------------------------------------------------------
fastify.delete('/groups/:id/permissions', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxGR401', { message: 'Token inválido o expirado.' });
    }

    const { id } = request.params;

    // Leer del body si viene, o de query params como fallback
    const body = request.body || {};
    const usuario_id   = body.usuario_id   || request.query?.usuario_id;
    const permiso_nombre = body.permiso_nombre || request.query?.permiso_nombre;

    if (!usuario_id || !permiso_nombre) {
        reply.code(400);
        return buildResponse(400, 'SxGR400', {
            message: 'usuario_id y permiso_nombre son obligatorios.'
        });
    }

    try {
        const { data: permiso } = await supabase
            .from('permisos')
            .select('id')
            .eq('nombre', permiso_nombre)
            .maybeSingle();

        if (!permiso) {
            reply.code(404);
            return buildResponse(404, 'SxGR404', { message: `Permiso '${permiso_nombre}' no existe.` });
        }

        const { error } = await supabase
            .from('grupo_usuario_permisos')
            .delete()
            .eq('grupo_id', id)
            .eq('usuario_id', usuario_id)
            .eq('permiso_id', permiso.id);

        if (error) throw error;

        return buildResponse(200, 'SxGR200', {
            message: 'Permiso revocado correctamente.'
        });

    } catch (err) {
        console.error('Error DELETE /groups/:id/permissions:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxGR500', { message: 'Error al revocar permiso.' });
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