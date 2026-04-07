// RP_Backend/service-groups/server.js
require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { createClient } = require('@supabase/supabase-js');
const { buildResponse } = require('../shared/responseHandler');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// --- RUTA: LISTAR TODOS LOS GRUPOS (group:view) ---
fastify.get('/groups/all', async (request, reply) => {
  try {
    const { data: groups, error } = await supabase.from('grupos').select('*');
    if (error) throw error;
    return buildResponse(200, 'SxGR200', groups);
  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxGR500', { message: 'Error al obtener grupos' });
  }
});

// --- RUTA: CREAR GRUPO (group:add) ---
fastify.post('/groups/create', async (request, reply) => {
  const { nombre, descripcion } = request.body || {}; 
  if (!nombre) {
    reply.code(400);
    return buildResponse(400, 'SxGR400', { message: 'El nombre es obligatorio' });
  }

  const token = request.headers.authorization?.split(' ')[1];
  try {
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) throw new Error('Usuario no válido');

    const { data: newGroup, error: groupError } = await supabase
      .from('grupos')
      .insert([{ nombre, descripcion, creador_id: user.id }])
      .select().single();

    if (groupError) throw groupError;

    await supabase.from('grupo_miembros').insert([{ grupo_id: newGroup.id, usuario_id: user.id }]);

    reply.code(201);
    return buildResponse(201, 'SxGR201', { message: 'Grupo creado', grupo: newGroup });
  } catch (err) {
    // ESTO ES CLAVE: Imprime el error real en tu terminal para leerlo
    console.error("ERROR DETALLADO:", err); 
    
    reply.code(500);
    return buildResponse(500, 'SxGR500', { 
      message: 'Error al crear grupo', 
      debug: err.message
    });
  }
});

// --- RUTA: EDITAR GRUPO (group:edit) ---
fastify.patch('/groups/edit/:id', async (request, reply) => { // Cambiado de /groups/:id a /groups/edit/:id
  const { id } = request.params;
  const updates = request.body || {};
  try {
    const { data, error } = await supabase.from('grupos').update(updates).eq('id', id).select().single();
    if (error) throw error;
    return buildResponse(200, 'SxGR200', { message: 'Grupo actualizado', grupo: data });
  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxGR500', { message: 'Error al editar grupo' });
  }
});

// --- RUTA: ELIMINAR GRUPO (group:delete) ---
fastify.delete('/groups/delete/:id', async (request, reply) => {
  const { id } = request.params;

  try {
    // 1. Borramos primero las dependencias (miembros y permisos)
    // Esto es necesario si no configuraste "ON DELETE CASCADE" en tu SQL
    await supabase.from('grupo_usuario_permisos').delete().eq('grupo_id', id);
    await supabase.from('grupo_miembros').delete().eq('grupo_id', id);

    // 2. Ahora sí borramos el grupo
    const { error } = await supabase.from('grupos').delete().eq('id', id);
    
    if (error) throw error;

    return buildResponse(200, 'SxGR200', { message: 'Grupo y sus dependencias eliminados exitosamente' });
  } catch (err) {
    console.error("ERROR AL ELIMINAR:", err);
    reply.code(500);
    return buildResponse(500, 'SxGR500', { message: 'Error al eliminar grupo', debug: err.message });
  }
});

// --- RUTA: ASIGNAR PERMISO (group:manage) ---
fastify.post('/groups/permissions', async (request, reply) => {
  const { grupo_id, usuario_id, permiso_nombre } = request.body || {};
  try {
    const { data: permiso } = await supabase.from('permisos').select('id').eq('nombre', permiso_nombre).single();
    if (!permiso) return buildResponse(404, 'SxGR404', { message: 'Permiso no existe' });

    const { data, error } = await supabase.from('grupo_usuario_permisos')
      .insert([{ grupo_id, usuario_id, permiso_id: permiso.id }]).select();

    if (error) throw error;

    reply.code(201);
    return buildResponse(201, 'SxGR201', { message: 'Permiso asignado', data: data[0] });
  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxGR500', { message: 'Error al asignar permiso' });
  }
});

const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 3002 });
    console.log(`Servicio de Grupos listo en puerto 3002`);
  } catch (err) {
    process.exit(1);
  }
};
start();