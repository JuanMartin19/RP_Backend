// RP_Backend/service-groups/server.js
require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { createClient } = require('@supabase/supabase-js');
const { buildResponse } = require('../shared/responseHandler');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// --- RUTA: CREAR GRUPO ---
fastify.post('/groups', async (request, reply) => {
  const { nombre, descripcion } = request.body || {}; 

  if (!nombre) {
    reply.code(400);
    return buildResponse(400, 'SxGR400', { message: 'El nombre del grupo es obligatorio' });
  }

  // 1. Extraer el token de los headers
  const token = request.headers.authorization?.split(' ')[1];

  try {
    // 2. Obtener la identidad del usuario a partir del token
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) throw new Error('Usuario no válido');

    // 3. Insertar en la tabla 'grupos'
    const { data: newGroup, error: groupError } = await supabase
      .from('grupos')
      .insert([{ nombre, descripcion, creador_id: user.id }])
      .select()
      .single();

    if (groupError) throw groupError;

    // 4. Registrar al creador como el primer miembro en 'grupo_miembros'
    const { error: memberError } = await supabase
      .from('grupo_miembros')
      .insert([{ grupo_id: newGroup.id, usuario_id: user.id }]);

    if (memberError) throw memberError;

    reply.code(201);
    return buildResponse(201, 'SxGR201', {
      message: 'Grupo creado exitosamente',
      grupo: newGroup
    });

  } catch (err) {
    fastify.log.error(err);
    reply.code(500);
    return buildResponse(500, 'SxGR500', { message: 'Error interno al crear el grupo', error: err.message });
  }
});

// --- LEVANTAR SERVIDOR ---
const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 3002 });
    console.log(`Servicio de Grupos corriendo en el puerto ${process.env.PORT || 3002}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();