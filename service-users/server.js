// RP_Backend/service-users/server.js
require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const supabase = require('./supabaseClient');
const { buildResponse } = require('../shared/responseHandler');

// --- RUTA DE PRUEBA ---
fastify.get('/health', async (request, reply) => {
  return buildResponse(200, 'SxUS200', { message: 'Servicio de usuarios funcionando correctamente' });
});

// --- RUTA DE REGISTRO ---
fastify.post('/auth/register', async (request, reply) => {
  // 1. Recibimos los datos del frontend (o de Postman)
  const { nombre_completo, username, email, password } = request.body;

  // 2. Validamos que no falte nada [cite: 157]
  if (!email || !password || !nombre_completo || !username) {
    reply.code(400); // 400 Bad Request
    return buildResponse(400, 'SxUS400', { message: 'Faltan campos obligatorios' });
  }

  try {
    // 3. Registramos la contraseña en Supabase Auth (el sistema seguro)
    const { data: authData, error: authError } = await supabase.auth.signUp({
      email: email,
      password: password,
    });

    if (authError) {
      reply.code(400);
      return buildResponse(400, 'SxUS400', { message: authError.message });
    }

    // 4. Guardamos los datos del perfil en tu tabla 'usuarios'
    // Usamos el mismo ID que nos generó Supabase Auth para mantenerlos vinculados
    const { data: userData, error: userError } = await supabase
      .from('usuarios')
      .insert([
        {
          id: authData.user.id,
          nombre_completo: nombre_completo,
          username: username,
          email: email
        }
      ])
      .select();

    if (userError) {
      reply.code(500);
      return buildResponse(500, 'SxUS500', { message: 'Error al guardar perfil', error: userError.message });
    }

    // 5. ¡Éxito! Devolvemos la respuesta universal
    reply.code(201); // 201 Created
    return buildResponse(201, 'SxUS201', { 
      message: 'Usuario registrado exitosamente', 
      user: userData[0] 
    });

  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxUS500', { message: 'Error interno del servidor' });
  }
});

// --- RUTA DE LOGIN ---
fastify.post('/auth/login', async (request, reply) => {
  const { email, password } = request.body;

  if (!email || !password) {
    reply.code(400);
    return buildResponse(400, 'SxUS400', { message: 'Faltan credenciales' });
  }

  try {
    // 1. Autenticar con Supabase (esto verifica si el correo y la contraseña coinciden)
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email: email,
      password: password,
    });

    if (authError) {
      reply.code(401); // 401 Unauthorized
      return buildResponse(401, 'SxUS401', { message: 'Credenciales inválidas' });
    }

    // 2. Traer los datos del perfil desde tu tabla 'usuarios'
    const { data: userData, error: userError } = await supabase
      .from('usuarios')
      .select('*')
      .eq('id', authData.user.id)
      .single(); // Esperamos un solo resultado

    if (userError) {
      reply.code(500);
      return buildResponse(500, 'SxUS500', { message: 'Error al obtener el perfil del usuario' });
    }

    // 3. ¡Éxito! Devolvemos el token (JWT) que nos dio Supabase y los datos del usuario
    reply.code(200);
    return buildResponse(200, 'SxUS200', {
      message: 'Login exitoso',
      token: authData.session.access_token, // Este es el JWT que usará el API Gateway
      user: userData
    });

  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxUS500', { message: 'Error interno del servidor' });
  }
});

// --- NUEVO: OBTENER TODOS LOS USUARIOS ---
fastify.get('/users', async (request, reply) => {
  try {
    // Nota: Por ahora listamos todos. 
    // Más adelante el API Gateway protegerá esta ruta para que solo entren los que tengan el permiso 'user:view'
    
    const { data: users, error } = await supabase
      .from('usuarios')
      .select('id, nombre_completo, username, email, fecha_inicio, last_login');

    if (error) throw error;

    reply.code(200);
    return buildResponse(200, 'SxUS200', users);

  } catch (err) {
    fastify.log.error(err);
    reply.code(500);
    return buildResponse(500, 'SxUS500', { message: 'Error al obtener usuarios' });
  }
});

// --- NUEVO: EDITAR UN PERFIL DE USUARIO ---
fastify.patch('/users/:id', async (request, reply) => {
  const userId = request.params.id; // El ID viene en la URL (ej. /users/123)
  const updates = request.body; // Los campos a actualizar (nombre_completo, telefono, etc.)

  // Prevenir que intenten cambiar el ID o la contraseña desde aquí
  delete updates.id;
  delete updates.password; 

  try {
    const { data: updatedUser, error } = await supabase
      .from('usuarios')
      .update(updates)
      .eq('id', userId)
      .select()
      .single();

    if (error) {
       reply.code(404); // 404 Not Found si el ID no existe
       return buildResponse(404, 'SxUS404', { message: 'Usuario no encontrado o sin cambios' });
    }

    reply.code(200);
    return buildResponse(200, 'SxUS200', {
      message: 'Perfil actualizado correctamente',
      user: updatedUser
    });

  } catch (err) {
    fastify.log.error(err);
    reply.code(500);
    return buildResponse(500, 'SxUS500', { message: 'Error interno al actualizar usuario' });
  }
});

// --- LEVANTAR SERVIDOR ---
const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 3001 });
    console.log(`Servicio de Usuarios corriendo en el puerto ${process.env.PORT || 3001}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();