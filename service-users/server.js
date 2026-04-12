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

    if (!nombre_completo || !username || !email || !password) {
        reply.code(400);
        return buildResponse(400, 'SxUS400', { message: 'Campos obligatorios faltantes.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // 1. Insertar el usuario en la tabla principal
        const { data: newUser, error: insertError } = await supabase
            .from('usuarios')
            .insert([{
                nombre_completo, username, email,
                password: hashedPassword, direccion, telefono
            }])
            .select().single();

        if (insertError) throw insertError;

        // 2. ASIGNAR PERMISOS POR DEFAULT (Globales)
        // Agregamos 'group:view' a la lista para que no aparezca el candado rojo al iniciar
        const { data: defaultPerms } = await supabase
            .from('permisos')
            .select('id')
            .in('nombre', ['user:edit:profile', 'user:view', 'group:view']);

        if (defaultPerms && defaultPerms.length > 0) {
            const permsToInsert = defaultPerms.map(p => ({
                usuario_id: newUser.id,
                permiso_id: p.id
            }));
            // Insertamos en la nueva tabla de permisos globales
            await supabase.from('usuario_permisos_globales').insert(permsToInsert);
        }

        reply.code(201);
        return buildResponse(201, 'SxUS201', { 
            message: 'Registro exitoso. Ya puedes ver tus grupos.', 
            user: newUser 
        });

    } catch (err) {
        console.error('Error en registro:', err);
        reply.code(500);
        return buildResponse(500, 'SxUS500', { message: 'Error interno del servidor.' });
    }
});

// -------------------------------------------------------
// LOGIN
// -------------------------------------------------------
fastify.post('/auth/login', async (request, reply) => {
    const { email, password } = request.body;

    try {
        const { data: usuario, error } = await supabase
            .from('usuarios')
            .select('*')
            .eq('email', email)
            .maybeSingle();

        if (error || !usuario) {
            reply.code(401);
            return buildResponse(401, 'SxUS401', { message: 'Credenciales incorrectas.' });
        }

        const passwordValido = await bcrypt.compare(password, usuario.password);
        if (!passwordValido) {
            reply.code(401);
            return buildResponse(401, 'SxUS401', { message: 'Credenciales incorrectas.' });
        }

        // ============================================================
        // NUEVO: ACTUALIZAR EL LAST_LOGIN AL INICIAR SESIÓN
        // ============================================================
        const fechaActual = new Date().toISOString();
        await supabase
            .from('usuarios')
            .update({ last_login: fechaActual })
            .eq('id', usuario.id);
        
        // Actualizamos el objeto en memoria para enviarlo al frontend
        usuario.last_login = fechaActual;

        // 1. Obtener Permisos Globales
        const { data: globales } = await supabase
            .from('usuario_permisos_globales')
            .select('permisos(nombre)')
            .eq('usuario_id', usuario.id);

        // 2. Obtener Permisos por Grupo
        const { data: porGrupo } = await supabase
            .from('grupo_usuario_permisos')
            .select('grupo_id, permisos(nombre)')
            .eq('usuario_id', usuario.id);

        // 3. Estructurar para el JWT
        const permisosJWT = {
            global: globales ? globales.map(g => g.permisos.nombre) : [],
            grupos: {}
        };

        if (porGrupo) {
            porGrupo.forEach(item => {
                if (!permisosJWT.grupos[item.grupo_id]) permisosJWT.grupos[item.grupo_id] = [];
                permisosJWT.grupos[item.grupo_id].push(item.permisos.nombre);
            });
        }

        const payload = {
            sub: usuario.id,
            username: usuario.username,
            permisos: permisosJWT
        };

        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

        return buildResponse(200, 'SxUS200', { token, user: usuario });

    } catch (err) {
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
        if (error || !usuario) return buildResponse(404, 'SxUS404', { message: 'No encontrado.' });
        return buildResponse(200, 'SxUS200', usuario);
    } catch (err) {
        reply.code(500).send(buildResponse(500, 'SxUS500', { message: 'Error.' }));
    }
});

// -------------------------------------------------------
// PATCH USUARIO (actualizar datos básicos)
// -------------------------------------------------------
fastify.patch('/users/:id', async (request, reply) => {
    const { id } = request.params;
    const body = { ...request.body };
    delete body.id; delete body.password; delete body.email; delete body.creado_en;

    try {
        const { data: updatedUser, error } = await supabase
            .from('usuarios')
            .update(body)
            .eq('id', id)
            .select().single();
        if (error) return buildResponse(404, 'SxUS404', { message: 'No encontrado.' });
        return buildResponse(200, 'SxUS200', { message: 'Actualizado.', user: updatedUser });
    } catch (err) {
        reply.code(500).send(buildResponse(500, 'SxUS500', { message: 'Error.' }));
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

// Obtener permisos globales de un usuario
fastify.get('/users/:id/permissions', async (request, reply) => {
    const { id } = request.params;
    const { data, error } = await supabase
        .from('usuario_permisos_globales')
        .select('permisos(nombre)')
        .eq('usuario_id', id);
    
    if (error) return buildResponse(500, 'SxUS500', { message: error.message });
    const lista = data.map(item => item.permisos);
    return buildResponse(200, 'SxUS200', lista);
});

fastify.post('/users/:id/permissions', async (request, reply) => {
    const { id } = request.params;
    const { permiso_nombre } = request.body;
    const { data: permiso } = await supabase.from('permisos').select('id').eq('nombre', permiso_nombre).single();
    if (!permiso) return buildResponse(404, 'SxUS404', { message: 'No encontrado.' });
    await supabase.from('usuario_permisos_globales').insert({ usuario_id: id, permiso_id: permiso.id });
    return buildResponse(201, 'SxUS201', { message: 'Permiso global asignado' });
});

fastify.delete('/users/:id/permissions', async (request, reply) => {
    const { id } = request.params;
    const { permiso_nombre } = request.body;
    const { data: permiso } = await supabase.from('permisos').select('id').eq('nombre', permiso_nombre).single();
    if (!permiso) return buildResponse(404, 'SxUS404', { message: 'No encontrado.' });
    await supabase.from('usuario_permisos_globales').delete().eq('usuario_id', id).eq('permiso_id', permiso.id);
    return buildResponse(200, 'SxUS200', { message: 'Permiso global removido' });
});

// -------------------------------------------------------
// START
// -------------------------------------------------------
const start = async () => {
    try {
        await fastify.listen({ port: process.env.PORT || 3001, host: '0.0.0.0' });
        console.log(`Servicio de Usuarios activo en puerto 3001`);
    } catch (err) {
        process.exit(1);
    }
};
start();