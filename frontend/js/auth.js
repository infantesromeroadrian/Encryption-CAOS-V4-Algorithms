/**
 * Módulo para la gestión de la autenticación
 */

const Auth = {
    // Clave para almacenar el token en localStorage
    TOKEN_KEY: 'secure_messaging_token',
    USER_KEY: 'secure_messaging_user',
    
    // Obtener el token almacenado
    getToken() {
        return localStorage.getItem(this.TOKEN_KEY);
    },
    
    // Guardar el token
    setToken(token) {
        localStorage.setItem(this.TOKEN_KEY, token);
    },
    
    // Eliminar el token
    removeToken() {
        localStorage.removeItem(this.TOKEN_KEY);
    },
    
    // Obtener el usuario almacenado
    getUser() {
        const userJson = localStorage.getItem(this.USER_KEY);
        return userJson ? JSON.parse(userJson) : null;
    },
    
    // Guardar el usuario
    setUser(user) {
        localStorage.setItem(this.USER_KEY, JSON.stringify(user));
    },
    
    // Eliminar el usuario
    removeUser() {
        localStorage.removeItem(this.USER_KEY);
    },
    
    // Verificar si el usuario está autenticado
    isAuthenticated() {
        return !!this.getToken();
    },
    
    // Iniciar sesión
    async login(username, password) {
        try {
            // Obtener el token
            const data = await API.auth.login(username, password);
            
            // Guardar el token
            this.setToken(data.access_token);
            
            // Obtener la información del usuario
            const user = await API.users.me(data.access_token);
            
            // Guardar la información del usuario
            this.setUser(user);
            
            return user;
        } catch (error) {
            console.error('Error al iniciar sesión:', error);
            throw error;
        }
    },
    
    // Registrar un nuevo usuario
    async register(username, email, password) {
        try {
            // Registrar el usuario
            const data = await API.auth.register(username, email, password);
            
            // Guardar el token
            this.setToken(data.access_token);
            
            // Guardar la información del usuario
            this.setUser(data);
            
            return data;
        } catch (error) {
            console.error('Error al registrar usuario:', error);
            throw error;
        }
    },
    
    // Cerrar sesión
    logout() {
        this.removeToken();
        this.removeUser();
    }
}; 