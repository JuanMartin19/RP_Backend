// RP_Backend/service-tickets/server.js
require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const { buildResponse } = require('../shared/responseHandler');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const JWT_SECRET = process.env.JWT_SECRET;

// --- CORS ---
fastify.register(require('@fastify/cors'), { origin: true });

// =======================================================
// SCHEMAS DE VALIDACIÓN (AJV nativo de Fastify)
// =======================================================

const createTicketSchema = {
    body: {
        type: 'object',
        required: ['grupo_id', 'titulo'],
        properties: {
            grupo_id: { type: ['integer', 'string'] },
            titulo: { type: 'string', minLength: 1 },
            descripcion: { type: ['string', 'null'] },
            prioridad: { type: 'string', enum: ['Alta', 'Media', 'Baja'] },
            asignado_id: { type: ['integer', 'null'] }
        }
    }
};

const updateTicketSchema = {
    body: {
        type: 'object',
        required: ['grupo_id'], // Obligatorio para validar permisos
        properties: {
            grupo_id: { type: ['integer', 'string'] },
            titulo: { type: 'string', minLength: 1 },
            descripcion: { type: ['string', 'null'] },
            prioridad: { type: 'string', enum: ['Alta', 'Media', 'Baja'] },
            asignado_id: { type: ['integer', 'null'] }
        }
    }
};

const statusTicketSchema = {
    body: {
        type: 'object',
        required: ['grupo_id', 'estado'],
        properties: {
            grupo_id: { type: ['integer', 'string'] },
            estado: { type: 'string', enum: ['Pendiente', 'En Progreso', 'Completado'] }
        }
    }
};

const commentSchema = {
    body: {
        type: 'object',
        required: ['texto'],
        properties: {
            texto: { type: 'string', minLength: 1 }
        }
    }
};

// Interceptor global para errores de validación de JSON Schema
fastify.setErrorHandler(function (error, request, reply) {
    if (error.validation) {
        reply.code(400).send(buildResponse(400, 'SxTK400', {
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
    const token = authHeader.split(' ')[1];
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch {
        return null;
    }
}

// -------------------------------------------------------
// HELPER — registrar en historial
// -------------------------------------------------------
async function registrarHistorial(ticket_id, autor_id, accion) {
    await supabase
        .from('ticket_historial')
        .insert([{ ticket_id, autor_id, accion }]);
}

// -------------------------------------------------------
// HEALTH CHECK
// -------------------------------------------------------
fastify.get('/health', async (request, reply) => {
    return buildResponse(200, 'SxTK200', { 
        message: 'Servicio de tickets funcionando correctamente' 
    });
});

// -------------------------------------------------------
// GET — listar tickets por grupo
// -------------------------------------------------------
fastify.get('/tickets/group/:grupo_id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxTK401', { message: 'Token inválido o expirado.' });
    }

    const { grupo_id } = request.params;
    const { asignado_id, estado, prioridad } = request.query;

    try {
        let query = supabase
            .from('tickets')
            .select(`
                id, titulo, descripcion, estado, prioridad, creado_en, grupo_id,
                autor:autor_id ( id, nombre_completo, username ),
                asignado:asignado_id ( id, nombre_completo, username )
            `);

        if (grupo_id !== 'all') {
            query = query.eq('grupo_id', grupo_id);
        }

        if (estado) query = query.eq('estado', estado);
        if (prioridad) query = query.eq('prioridad', prioridad);
        if (asignado_id) query = query.eq('asignado_id', asignado_id);

        const { data: tickets, error } = await query.order('creado_en', { ascending: false });

        if (error) throw error;

        return buildResponse(200, 'SxTK200', tickets || []);

    } catch (err) {
        console.error('Error GET /tickets/group/:grupo_id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxTK500', { message: 'Error al obtener tickets.' });
    }
});

// -------------------------------------------------------
// GET — ticket por ID con comentarios e historial
// -------------------------------------------------------
fastify.get('/tickets/:id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxTK401', { message: 'Token inválido o expirado.' });
    }

    const { id } = request.params;

    try {
        const { data: ticket, error } = await supabase
            .from('tickets')
            .select(`
                id, grupo_id, titulo, descripcion, estado, prioridad, creado_en, 
                autor:autor_id ( id, nombre_completo, username ),
                asignado:asignado_id ( id, nombre_completo, username )
            `)
            .eq('id', id)
            .maybeSingle();

        if (error || !ticket) {
            reply.code(404);
            return buildResponse(404, 'SxTK404', { message: 'Ticket no encontrado.' });
        }

        const { data: comentarios } = await supabase
            .from('ticket_comentarios')
            .select(`
                id, texto, creado_en,
                autor:autor_id ( id, nombre_completo, username )
            `)
            .eq('ticket_id', id)
            .order('creado_en', { ascending: true });

        const { data: historial } = await supabase
            .from('ticket_historial')
            .select(`
                id, accion, creado_en,
                autor:autor_id ( id, nombre_completo, username )
            `)
            .eq('ticket_id', id)
            .order('creado_en', { ascending: true });

        return buildResponse(200, 'SxTK200', {
            ...ticket,
            comentarios: comentarios || [],
            historial: historial || []
        });

    } catch (err) {
        console.error('Error GET /tickets/:id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxTK500', { message: 'Error interno del servidor.' });
    }
});

// -------------------------------------------------------
// POST — crear ticket (Con Schema)
// -------------------------------------------------------
fastify.post('/tickets', { schema: createTicketSchema }, async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxTK401', { message: 'Token inválido o expirado.' });
    }

    const { grupo_id, titulo, descripcion, prioridad, asignado_id } = request.body;

    try {
        const { data: nuevoTicket, error } = await supabase
            .from('tickets')
            .insert([{
                grupo_id,
                titulo,
                descripcion: descripcion || null,
                autor_id: usuario.sub,
                asignado_id: asignado_id || null,
                prioridad: prioridad || 'Media',
                estado: 'Pendiente'
            }])
            .select()
            .single();

        if (error) throw error;

        await registrarHistorial(nuevoTicket.id, usuario.sub, 'Ticket creado');

        reply.code(201);
        return buildResponse(201, 'SxTK201', { 
            message: 'Ticket creado correctamente.', 
            ticket: nuevoTicket 
        });

    } catch (err) {
        console.error('Error POST /tickets:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxTK500', { message: 'Error al crear el ticket.' });
    }
});

// -------------------------------------------------------
// PATCH — editar ticket (Con Schema)
// -------------------------------------------------------
fastify.patch('/tickets/:id', { schema: updateTicketSchema }, async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) return reply.code(401).send(buildResponse(401, 'SxTK401', { message: 'Token inválido.' }));

    const { id } = request.params;
    const { grupo_id, ...datosAActualizar } = request.body;

    try {
        const permisosDelGrupo = usuario.permisos?.grupos[String(grupo_id)] || [];
        const tienePermisoEdit = permisosDelGrupo.includes('ticket:edit') || usuario.permisos?.global.includes('ticket:manage');

        if (!tienePermisoEdit) {
            return reply.code(403).send(buildResponse(403, 'SxTK403', { message: 'No tienes permiso para editar tickets en este grupo.' }));
        }

        const { data: ticketActualizado, error } = await supabase
            .from('tickets')
            .update(datosAActualizar)
            .eq('id', id)
            .select()
            .single();

        if (error) throw error;

        await registrarHistorial(id, usuario.sub, `Ticket editado por el usuario.`);

        return buildResponse(200, 'SxTK200', { 
            message: 'Ticket actualizado correctamente.', 
            ticket: ticketActualizado 
        });

    } catch (err) {
        console.error('Error PATCH /tickets/:id:', err.message);
        reply.code(500).send(buildResponse(500, 'SxTK500', { message: 'Error al editar el ticket.' }));
    }
});

// -------------------------------------------------------
// PATCH — cambiar estado del ticket (Con Schema)
// -------------------------------------------------------
fastify.patch('/tickets/:id/status', { schema: statusTicketSchema }, async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxTK401', { message: 'Token inválido o expirado.' });
    }

    const { id } = request.params;
    const { estado } = request.body; 

    try {
        const { data: ticket, error: fetchError } = await supabase
            .from('tickets')
            .select('id, estado, asignado_id')
            .eq('id', id)
            .maybeSingle();

        if (fetchError || !ticket) {
            reply.code(404);
            return buildResponse(404, 'SxTK404', { message: 'Ticket no encontrado.' });
        }

        if (ticket.asignado_id !== usuario.sub) {
            reply.code(403);
            return buildResponse(403, 'SxTK403', { 
                message: 'Solo puedes cambiar el estado de tickets asignados a ti.' 
            });
        }

        const estadoAnterior = ticket.estado;

        const { data: ticketActualizado, error: updateError } = await supabase
            .from('tickets')
            .update({ estado })
            .eq('id', id)
            .select()
            .single();

        if (updateError) throw updateError;

        await registrarHistorial(
            id, 
            usuario.sub, 
            `Estado cambiado: ${estadoAnterior} → ${estado}`
        );

        return buildResponse(200, 'SxTK200', { 
            message: 'Estado actualizado correctamente.', 
            ticket: ticketActualizado 
        });

    } catch (err) {
        console.error('Error PATCH /tickets/:id/status:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxTK500', { message: 'Error al cambiar el estado.' });
    }
});

// -------------------------------------------------------
// DELETE — eliminar ticket
// -------------------------------------------------------
fastify.delete('/tickets/:id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxTK401', { message: 'Token inválido o expirado.' });
    }

    const { id } = request.params;

    try {
        const { error } = await supabase
            .from('tickets')
            .delete()
            .eq('id', id);

        if (error) throw error;

        return buildResponse(200, 'SxTK200', { message: 'Ticket eliminado correctamente.' });

    } catch (err) {
        console.error('Error DELETE /tickets/:id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxTK500', { message: 'Error al eliminar el ticket.' });
    }
});

// -------------------------------------------------------
// POST — agregar comentario (Con Schema)
// -------------------------------------------------------
fastify.post('/tickets/:id/comments', { schema: commentSchema }, async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxTK401', { message: 'Token inválido o expirado.' });
    }

    const { id } = request.params;
    const { texto } = request.body;

    try {
        const { data: comentario, error } = await supabase
            .from('ticket_comentarios')
            .insert([{ 
                ticket_id: id, 
                autor_id: usuario.sub, 
                texto: texto.trim() 
            }])
            .select(`
                id, texto, creado_en,
                autor:autor_id ( id, nombre_completo, username )
            `)
            .single();

        if (error) throw error;

        reply.code(201);
        return buildResponse(201, 'SxTK201', { 
            message: 'Comentario agregado correctamente.', 
            comentario 
        });

    } catch (err) {
        console.error('Error POST /tickets/:id/comments:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxTK500', { message: 'Error al agregar comentario.' });
    }
});

// -------------------------------------------------------
// DELETE — eliminar comentario
// -------------------------------------------------------
fastify.delete('/tickets/:id/comments/:comentario_id', async (request, reply) => {
    const usuario = verificarToken(request);
    if (!usuario) {
        reply.code(401);
        return buildResponse(401, 'SxTK401', { message: 'Token inválido o expirado.' });
    }

    const { comentario_id } = request.params;

    try {
        const { data: comentario } = await supabase
            .from('ticket_comentarios')
            .select('autor_id')
            .eq('id', comentario_id)
            .maybeSingle();

        if (!comentario) {
            reply.code(404);
            return buildResponse(404, 'SxTK404', { message: 'Comentario no encontrado.' });
        }

        if (comentario.autor_id !== usuario.sub) {
            reply.code(403);
            return buildResponse(403, 'SxTK403', { message: 'No puedes eliminar comentarios de otros usuarios.' });
        }

        const { error } = await supabase
            .from('ticket_comentarios')
            .delete()
            .eq('id', comentario_id);

        if (error) throw error;

        return buildResponse(200, 'SxTK200', { message: 'Comentario eliminado correctamente.' });

    } catch (err) {
        console.error('Error DELETE /tickets/:id/comments/:comentario_id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxTK500', { message: 'Error al eliminar comentario.' });
    }
});

// -------------------------------------------------------
// START
// -------------------------------------------------------
const start = async () => {
    try {
        await fastify.listen({ port: process.env.PORT || 3003, host: '0.0.0.0' });
        console.log(`Servicio de Tickets activo en puerto ${process.env.PORT || 3003}`);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

start();