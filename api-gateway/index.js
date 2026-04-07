// RP_Backend/api-gateway/index.js
require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const proxy = require('@fastify/http-proxy');
const { createClient } = require('@supabase/supabase-js');
const { buildResponse } = require('../shared/responseHandler');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// --- NUEVO: CONFIGURACIÓN DE RATE LIMITING ---
fastify.register(require('@fastify/rate-limit'), {
  max: 100, // Máximo 100 peticiones
  timeWindow: '1 minute', // En un lapso de 1 minuto
  errorResponseBuilder: function (request, context) {
    // Si se pasan de 100, devolvemos el error 429 con nuestro esquema JSON universal
    return buildResponse(429, 'SxGW429', { message: 'Too many requests' });
  }
});
// ---------------------------------------------

// Configuración del Proxy (Redirigir tráfico a Users)
fastify.register(proxy, {
  upstream: 'http://localhost:3001',
  prefix: '/users-service', 
  rewritePrefix: '' 
});

// Middleware (Hook) para validar el token
fastify.addHook('preHandler', async (request, reply) => {
  const isAuthRoute = request.url.includes('/auth/login') || request.url.includes('/auth/register');
  if (isAuthRoute) return;

  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    reply.code(401);
    return buildResponse(401, 'SxGW401', { message: 'Token no proporcionado o formato inválido' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      reply.code(403);
      return buildResponse(403, 'SxGW403', { message: 'Token inválido o expirado' });
    }

    request.user = data.user; 
  } catch (err) {
    reply.code(500);
    return buildResponse(500, 'SxGW500', { message: 'Error interno al validar token' });
  }
});

// Rutas del Gateway (Puntos de entrada públicos)
fastify.post('/auth/register', async (request, reply) => {
    const res = await fastify.inject({
        method: 'POST',
        url: '/users-service/auth/register',
        payload: request.body
    });
    reply.code(res.statusCode).send(res.json());
});

fastify.post('/auth/login', async (request, reply) => {
     const res = await fastify.inject({
        method: 'POST',
        url: '/users-service/auth/login',
        payload: request.body
    });
    reply.code(res.statusCode).send(res.json());
});

// Ruta Protegida de Prueba
fastify.get('/profile-test', async (request, reply) => {
  return buildResponse(200, 'SxGW200', { 
      message: '¡El Gateway verificó tu token con Supabase exitosamente!',
      userId: request.user.id
  });
});

// Levantar el Gateway
const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 3000 });
    console.log(`API Gateway corriendo en el puerto ${process.env.PORT || 3000}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();