// RP_Backend/service-tickets/server.js
require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { createClient } = require('@supabase/supabase-js');
const { buildResponse } = require('../shared/responseHandler');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// --- RUTA: CREAR TICKET (ticket:add) ---
fastify.post('/tickets/create', async (request, reply) => {
  const { grupo_id, titulo, descripcion, prioridad, fecha_limite } = request.body || {};

  if (!grupo_id || !titulo) {
    reply.code(400);
    return buildResponse(400, 'SxTK400', { message: 'Grupo y Título son obligatorios' });
  }

  const token = request.headers.authorization?.split(' ')[1];

  try {
    // 1. Obtener quién es el autor desde el token
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) throw new Error('Usuario no autenticado');

    // 2. Insertar ticket en Postgres
    const { data: newTicket, error: tkError } = await supabase
      .from('tickets')
      .insert([{
        grupo_id,
        titulo,
        descripcion,
        autor_id: user.id,
        estado: 'Abierto', // Estado inicial por defecto
        prioridad: prioridad || 'Media',
        fecha_limite
      }])
      .select().single();

    if (tkError) throw tkError;

    reply.code(201);
    return buildResponse(201, 'SxTK201', { message: 'Ticket creado exitosamente', ticket: newTicket });

  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxTK500', { message: 'Error al crear ticket', debug: err.message });
  }
});

// --- RUTA: LISTAR TICKETS POR GRUPO (ticket:view) ---
fastify.get('/tickets/group/:grupo_id', async (request, reply) => {
  const { grupo_id } = request.params;

  try {
    const { data: tickets, error } = await supabase
      .from('tickets')
      .select('*')
      .eq('grupo_id', grupo_id)
      .order('creado_en', { ascending: false });

    if (error) throw error;

    return buildResponse(200, 'SxTK200', tickets);
  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxTK500', { message: 'Error al obtener tickets' });
  }
});

// --- EDITAR TICKET (ticket:edit) ---
fastify.patch('/tickets/edit/:id', async (request, reply) => {
  const { id } = request.params;
  const updates = request.body || {};

  try {
    const { data, error } = await supabase
      .from('tickets')
      .update(updates)
      .eq('id', id)
      .select().single();

    if (error) throw error;
    return buildResponse(200, 'SxTK200', { message: 'Ticket actualizado', ticket: data });
  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxTK500', { message: 'Error al editar ticket' });
  }
});

// --- CAMBIAR ESTADO (ticket:edit:state) ---
// Ruta específica para el Workflow (Abierto -> En Proceso -> Cerrado)
fastify.patch('/tickets/status/:id', async (request, reply) => {
  const { id } = request.params;
  const { estado } = request.body || {};

  if (!estado) {
    reply.code(400);
    return buildResponse(400, 'SxTK400', { message: 'El nuevo estado es obligatorio' });
  }

  try {
    const { data, error } = await supabase
      .from('tickets')
      .update({ estado })
      .eq('id', id)
      .select().single();

    if (error) throw error;
    return buildResponse(200, 'SxTK200', { message: 'Estado del ticket actualizado', ticket: data });
  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxTK500', { message: 'Error al cambiar estado' });
  }
});

// --- ELIMINAR TICKET (ticket:delete) ---
fastify.delete('/tickets/delete/:id', async (request, reply) => {
  const { id } = request.params;

  try {
    // Primero borramos historial o comentarios si existen (Integridad referencial)
    await supabase.from('ticket_comentarios').delete().eq('ticket_id', id);
    await supabase.from('ticket_historial').delete().eq('ticket_id', id);

    const { error } = await supabase.from('tickets').delete().eq('id', id);
    if (error) throw error;

    return buildResponse(200, 'SxTK200', { message: 'Ticket eliminado exitosamente' });
  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxTK500', { message: 'Error al eliminar ticket' });
  }
});

// --- AGREGAR COMENTARIO (ticket:edit:comment) ---
fastify.post('/tickets/comment', async (request, reply) => {
  const { ticket_id, texto } = request.body || {};
  const token = request.headers.authorization?.split(' ')[1];

  try {
    const { data: { user } } = await supabase.auth.getUser(token);
    
    const { data, error } = await supabase
      .from('ticket_comentarios')
      .insert([{ ticket_id, autor_id: user.id, texto }])
      .select().single();

    if (error) throw error;
    return buildResponse(201, 'SxTK201', { message: 'Comentario agregado', comentario: data });
  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxTK500', { message: 'Error al agregar comentario' });
  }
});

const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 3003 });
    console.log(`Servicio de Tickets listo en puerto 3003`);
  } catch (err) {
    process.exit(1);
  }
};
start();