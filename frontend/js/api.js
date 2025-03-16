/**
 * Módulo para la comunicación con la API
 */

const API = {
    // URL base de la API
    baseUrl: 'http://localhost:8000/api/v1',
    
    // Método para realizar peticiones a la API
    async request(endpoint, method = 'GET', data = null, token = null) {
        const url = `${this.baseUrl}${endpoint}`;
        
        const headers = {
            'Content-Type': 'application/json'
        };
        
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        const options = {
            method,
            headers,
            credentials: 'include'
        };
        
        if (data && (method === 'POST' || method === 'PUT')) {
            options.body = JSON.stringify(data);
        }
        
        try {
            const response = await fetch(url, options);
            
            // Si la respuesta no es exitosa, lanzar un error
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Error en la petición');
            }
            
            // Si la respuesta es exitosa, devolver los datos
            if (response.status !== 204) { // No Content
                return await response.json();
            }
            
            return null;
        } catch (error) {
            console.error('Error en la petición:', error);
            throw error;
        }
    },
    
    // Métodos para la autenticación
    auth: {
        // Iniciar sesión
        async login(username, password) {
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);
            
            const response = await fetch(`${API.baseUrl}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: formData
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Error al iniciar sesión');
            }
            
            return await response.json();
        },
        
        // Registrar un nuevo usuario
        async register(username, email, password) {
            return await API.request('/auth/register', 'POST', {
                username,
                email,
                password,
                is_active: true
            });
        }
    },
    
    // Métodos para los usuarios
    users: {
        // Obtener el usuario actual
        async me(token) {
            return await API.request('/users/me', 'GET', null, token);
        },
        
        // Obtener la lista de usuarios
        async list(token) {
            return await API.request('/users', 'GET', null, token);
        },
        
        // Obtener un usuario por su ID
        async get(userId, token) {
            return await API.request(`/users/${userId}`, 'GET', null, token);
        }
    },
    
    // Métodos para los mensajes
    messages: {
        // Enviar un mensaje
        async send(recipientId, content, expiresInHours, password, token) {
            const data = {
                recipient_id: recipientId,
                content,
                password
            };
            
            if (expiresInHours) {
                data.expires_in_hours = parseInt(expiresInHours);
            }
            
            return await API.request('/messages', 'POST', data, token);
        },
        
        // Obtener los mensajes recibidos
        async received(token) {
            return await API.request('/messages/received', 'GET', null, token);
        },
        
        // Obtener los mensajes enviados
        async sent(token) {
            return await API.request('/messages/sent', 'GET', null, token);
        },
        
        // Obtener un mensaje por su ID
        async get(messageId, password, token) {
            return await API.request(`/messages/${messageId}?password=${encodeURIComponent(password)}`, 'GET', null, token);
        }
    }
}; 