// RP_Backend/service-users/server.js
require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { supabase } = require('./supabaseClient');
const { buildResponse } = require('../shared/responseHandler');

const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 10;

// --- CORS ---
fastify.register(require('@fastify/cors'), { origin: true });

// -------------------------------------------------------
// HEALTH CHECK
// -------------------------------------------------------
fastify.get('/health', async (request, reply) => {
    return buildResponse(200, 'SxUS200', { 
        message: 'Servicio de usuarios funcionando correctamente' 
    });
});

// -------------------------------------------------------
// REGISTER
// -------------------------------------------------------
fastify.post('/auth/register', async (request, reply) => {
    const { nombre_completo, username, email, password, direccion, telefono } = request.body;

    // 1. Validar campos obligatorios
    if (!nombre_completo || !username || !email || !password) {
        reply.code(400);
        return buildResponse(400, 'SxUS400', { 
            message: 'nombre_completo, username, email y password son obligatorios.' 
        });
    }

    // 2. Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        reply.code(400);
        return buildResponse(400, 'SxUS400', { message: 'Formato de email inválido.' });
    }

    // 3. Validar longitud de password
    if (password.length < 6) {
        reply.code(400);
        return buildResponse(400, 'SxUS400', { 
            message: 'La contraseña debe tener al menos 6 caracteres.' 
        });
    }

    try {
        // 4. Verificar si email o username ya existen
        const { data: existingUser } = await supabase
            .from('usuarios')
            .select('username, email')
            .or(`email.eq.${email},username.eq.${username}`)
            .maybeSingle();

        if (existingUser) {
            reply.code(400);
            if (existingUser.email === email) {
                return buildResponse(400, 'SxUS400', { message: 'El correo ya está registrado.' });
            }
            if (existingUser.username === username) {
                return buildResponse(400, 'SxUS400', { message: 'El nombre de usuario no está disponible.' });
            }
        }

        // 5. Hashear password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // 6. Insertar usuario
        const { data: newUser, error: insertError } = await supabase
            .from('usuarios')
            .insert([{
                nombre_completo,
                username,
                email,
                password: hashedPassword,
                direccion: direccion || null,
                telefono: telefono || null
            }])
            .select('id, nombre_completo, username, email, creado_en')
            .single();

        if (insertError) {
            console.error('Error al insertar usuario:', insertError.message);
            reply.code(500);
            return buildResponse(500, 'SxUS500', { message: 'Error al crear el usuario.' });
        }

        reply.code(201);
        return buildResponse(201, 'SxUS201', { 
            message: '¡Registro exitoso!',
            user: newUser
        });

    } catch (err) {
        console.error('FATAL register:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxUS500', { message: 'Error interno del servidor.' });
    }
});

// -------------------------------------------------------
// LOGIN
// -------------------------------------------------------
fastify.post('/auth/login', async (request, reply) => {
    const { email, password } = request.body;

    // 1. Validar campos obligatorios
    if (!email || !password) {
        reply.code(400);
        return buildResponse(400, 'SxUS400', { 
            message: 'Email y password son obligatorios.' 
        });
    }

    try {
        // 2. Buscar usuario por email
        const { data: usuario, error } = await supabase
            .from('usuarios')
            .select('*')
            .eq('email', email)
            .maybeSingle();

        if (error || !usuario) {
            reply.code(401);
            return buildResponse(401, 'SxUS401', { message: 'Credenciales incorrectas.' });
        }

        // 3. Verificar password
        const passwordValido = await bcrypt.compare(password, usuario.password);
        if (!passwordValido) {
            reply.code(401);
            return buildResponse(401, 'SxUS401', { message: 'Credenciales incorrectas.' });
        }

        // 4. Traer permisos del usuario por grupo
        const { data: permisosData } = await supabase
            .from('grupo_usuario_permisos')
            .select(`
                grupo_id,
                permisos ( nombre )
            `)
            .eq('usuario_id', usuario.id);

        // Agrupar permisos por grupo: { "1": ["tickets:add", "tickets:move"], "2": [...] }
        const permisosPorGrupo = {};
        if (permisosData) {
            permisosData.forEach(({ grupo_id, permisos }) => {
                if (!permisosPorGrupo[grupo_id]) permisosPorGrupo[grupo_id] = [];
                permisosPorGrupo[grupo_id].push(permisos.nombre);
            });
        }

        // 5. Generar JWT
        const payload = {
            sub: usuario.id,
            username: usuario.username,
            email: usuario.email,
            permisos: permisosPorGrupo
        };

        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

        // 6. Actualizar last_login
        await supabase
            .from('usuarios')
            .update({ last_login: new Date().toISOString() })
            .eq('id', usuario.id);

        // 7. Responder sin exponer la password
        const { password: _, ...usuarioSinPassword } = usuario;

        return buildResponse(200, 'SxUS200', {
            message: 'Acceso correcto.',
            token,
            user: usuarioSinPassword
        });

    } catch (err) {
        console.error('FATAL login:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxUS500', { message: 'Error interno del servidor.' });
    }
});

// -------------------------------------------------------
// GET TODOS LOS USUARIOS (requiere token — lo valida el API Gateway)
// -------------------------------------------------------
fastify.get('/users', async (request, reply) => {
    try {
        const { data: users, error } = await supabase
            .from('usuarios')
            .select('id, nombre_completo, username, email, telefono, direccion, last_login, creado_en');

        if (error) throw error;

        return buildResponse(200, 'SxUS200', users);

    } catch (err) {
        console.error('Error GET /users:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxUS500', { message: 'Error al obtener usuarios.' });
    }
});

// -------------------------------------------------------
// GET USUARIO POR ID
// -------------------------------------------------------
fastify.get('/users/:id', async (request, reply) => {
    const { id } = request.params;

    try {
        const { data: usuario, error } = await supabase
            .from('usuarios')
            .select('id, nombre_completo, username, email, telefono, direccion, last_login, creado_en')
            .eq('id', id)
            .maybeSingle();

        if (error || !usuario) {
            reply.code(404);
            return buildResponse(404, 'SxUS404', { message: 'Usuario no encontrado.' });
        }

        return buildResponse(200, 'SxUS200', usuario);

    } catch (err) {
        console.error('Error GET /users/:id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxUS500', { message: 'Error interno del servidor.' });
    }
});

// -------------------------------------------------------
// PATCH USUARIO (actualizar datos básicos)
// -------------------------------------------------------
fastify.patch('/users/:id', async (request, reply) => {
    const { id } = request.params;
    const body = { ...request.body };

    // Campos que no se pueden modificar desde aquí
    delete body.id;
    delete body.password;
    delete body.email;
    delete body.creado_en;

    if (Object.keys(body).length === 0) {
        reply.code(400);
        return buildResponse(400, 'SxUS400', { message: 'No hay campos válidos para actualizar.' });
    }

    try {
        const { data: updatedUser, error } = await supabase
            .from('usuarios')
            .update(body)
            .eq('id', id)
            .select('id, nombre_completo, username, email, telefono, direccion, last_login, creado_en')
            .single();

        if (error) {
            reply.code(404);
            return buildResponse(404, 'SxUS404', { message: 'Usuario no encontrado.' });
        }

        return buildResponse(200, 'SxUS200', { 
            message: 'Perfil actualizado correctamente.', 
            user: updatedUser 
        });

    } catch (err) {
        console.error('Error PATCH /users/:id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxUS500', { message: 'Error interno del servidor.' });
    }
});

// -------------------------------------------------------
// DELETE USUARIO
// -------------------------------------------------------
fastify.delete('/users/:id', async (request, reply) => {
    const { id } = request.params;

    try {
        const { error } = await supabase
            .from('usuarios')
            .delete()
            .eq('id', id);

        if (error) {
            reply.code(404);
            return buildResponse(404, 'SxUS404', { message: 'Usuario no encontrado.' });
        }

        return buildResponse(200, 'SxUS200', { message: 'Usuario eliminado correctamente.' });

    } catch (err) {
        console.error('Error DELETE /users/:id:', err.message);
        reply.code(500);
        return buildResponse(500, 'SxUS500', { message: 'Error interno del servidor.' });
    }
});

// -------------------------------------------------------
// START
// -------------------------------------------------------
const start = async () => {
    try {
        await fastify.listen({ port: process.env.PORT || 3001, host: '0.0.0.0' });
        console.log(`Servicio de Usuarios activo en puerto ${process.env.PORT || 3001}`);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

start();